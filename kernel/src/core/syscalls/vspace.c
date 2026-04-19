#include <stdint.h>

#include "compiler.h"
#include "core/capability.h"
#include "core/errors.h"
#include "core/syscalls.h"
#include "cpu/smp.h"
#include "libs/math.h"
#include "memory/memory.h"
#include "memory/pagemap.h"
#include "memory/vm_object.h"
#include "memory/vma.h"
#include "sched/process.h"

static uint32_t translate_uflags_to_vmm_flags(uint32_t u_flags, vmo_type_t vmo_type) {
    uint32_t k_flags = VMM_FLAG_USER;

    if (u_flags & VSPACE_PROT_READ) k_flags |= VMM_FLAG_READ;
    if (u_flags & VSPACE_PROT_WRITE) k_flags |= VMM_FLAG_WRITE;
    if (u_flags & VSPACE_PROT_EXEC) k_flags |= VMM_FLAG_EXECUTE;

    if (u_flags & VSPACE_MAP_EXACT) k_flags |= VMM_FLAG_FIXED_NOREPLACE;
    if (u_flags & VSPACE_MAP_OVERWRITE) k_flags |= VMM_FLAG_FIXED;

    if (u_flags & VSPACE_MAP_STACK) k_flags |= VMM_FLAG_STACK | VMM_FLAG_GUARD;

    if (u_flags & VSPACE_MAP_SHADOW)
        k_flags |= VMM_FLAG_PRIVATE | VMM_FLAG_COW;
    else
        k_flags |= VMM_FLAG_SHARED;

    if (vmo_type == VM_OBJ_PHYSICAL) k_flags |= VMM_FLAG_MMIO;

    if (u_flags & VSPACE_MAP_WIRE)
        k_flags |= VMM_FLAG_POPULATE | VMM_FLAG_LOCKED;
    else if (u_flags & VSPACE_MAP_POPULATE)
        k_flags |= VMM_FLAG_POPULATE;
    else
        k_flags |= VMM_FLAG_DEMAND;

    return k_flags;
}

static size_t get_page_size(size_t u_flags) {
    if (u_flags & VSPACE_MAP_PAGE_1G) return PAGE_SIZE_LARGE;
    if (u_flags & VSPACE_MAP_PAGE_2M) return PAGE_SIZE_MEDIUM;
    return PAGE_SIZE_SMALL;
}

static struct vm_space*
resolve_vspace(struct cnode* root, uint64_t cap_id, uint16_t required_rights) {
    if (cap_id == 0) return smp_current_core()->curr_thread->owner->vspace;
    return cap_resolve(root, cap_id, required_rights, CAP_TYPE_VSPACE);
}

int sys_vmo_create(size_t size, uint32_t flags, uint64_t* out_vmo_cap) {
    struct process* proc = smp_current_core()->curr_thread->owner;
    if (unlikely(!proc || !out_vmo_cap || size == 0)) return ERR_INVALID;

    vmo_type_t type = (flags & VMO_CREATE_PHYSICAL) ? VM_OBJ_PHYSICAL : VM_OBJ_ANONYMOUS;

    if (type == VM_OBJ_PHYSICAL) return ERR_DENIED;

    vm_object_t* vmo = vm_object_create(type, size);
    if (!vmo) return ERR_NO_MEM;

    uint64_t cap_id;
    struct capability* cap = cap_alloc(proc->root_cnode, &cap_id);
    if (!cap) {
        vm_object_deref(vmo);
        return ERR_CAP_EXHAUSTED;
    }

    acquire_qspinlock(&cap->lock);
    atomic_store_explicit(&cap->object_ptr, (uintptr_t)vmo, memory_order_release);
    cap->type   = CAP_TYPE_VMO;
    cap->rights = RIGHT_READ | RIGHT_WRITE | RIGHT_EXECUTE | RIGHT_MAP;
    release_qspinlock(&cap->lock);

    if (copy_to_user(out_vmo_cap, &cap_id, sizeof(uint64_t)) != 0) {
        sys_cap_close(proc->root_cnode, cap_id);
        return ERR_FAULT;
    }

    return ERR_OK;
}

uintptr_t sys_vspace_map(
    uint64_t vspace_cap,
    uint64_t vmo_cap,
    size_t vmo_offset,
    uintptr_t hint_addr,
    size_t size,
    uint32_t map_flags
) {
    struct process* proc = smp_current_core()->curr_thread->owner;
    struct cnode* root   = proc->root_cnode;

    struct vm_space* space = resolve_vspace(root, vspace_cap, RIGHT_WRITE);
    if (!space) return (uintptr_t)ERR_DENIED;

    uint16_t req_vmo_rights = RIGHT_MAP;

    if (map_flags & VSPACE_PROT_READ) req_vmo_rights |= RIGHT_READ;
    if (map_flags & VSPACE_PROT_EXEC) req_vmo_rights |= RIGHT_EXECUTE;

    if ((map_flags & VSPACE_PROT_WRITE) && !(map_flags & VSPACE_MAP_SHADOW))
        req_vmo_rights |= RIGHT_WRITE;

    vm_object_t* vmo = cap_resolve(root, vmo_cap, req_vmo_rights, CAP_TYPE_VMO);
    if (!vmo) return (uintptr_t)ERR_DENIED;

    if (unlikely(vmo_offset + size > vmo->size)) return (uintptr_t)ERR_INVALID;

    uint32_t vmm_flags = translate_uflags_to_vmm_flags(map_flags, vmo->type);
    cache_type_t cache = (vmo->type == VM_OBJ_PHYSICAL) ? CACHE_UNCACHEABLE : CACHE_WRITE_BACK;

    size_t page_size = get_page_size(map_flags);

    void* mapped_addr =
        vmalloc(space, (void*)hint_addr, size, vmm_flags, cache, page_size, vmo, vmo_offset);

    if (!mapped_addr) {
        if (map_flags & VSPACE_MAP_EXACT) return (uintptr_t)ERR_EXIST;
        return (uintptr_t)ERR_NO_MEM;
    }

    return (uintptr_t)mapped_addr;
}

int sys_vspace_unmap(uint64_t vspace_cap, uintptr_t addr, size_t size) {
    struct process* proc = smp_current_core()->curr_thread->owner;

    struct vm_space* space = resolve_vspace(proc->root_cnode, vspace_cap, RIGHT_WRITE);
    if (!space) return ERR_DENIED;

    if (!is_aligned(addr, PAGE_SIZE_SMALL) || size == 0) return ERR_INVALID;
    vmfree(space, (void*)addr, size);
    return ERR_OK;
}

int sys_vmo_resize(uint64_t vmo_cap, size_t new_size) {
    struct process* proc = smp_current_core()->curr_thread->owner;
    if (unlikely(!proc || !proc->root_cnode)) return ERR_INVALID;

    vm_object_t* vmo = cap_resolve(proc->root_cnode, vmo_cap, RIGHT_WRITE, CAP_TYPE_VMO);
    if (!vmo) return ERR_DENIED;
    if (vmo->type == VM_OBJ_PHYSICAL) return ERR_PERM;

    size_t aligned_new = align_up(new_size, PAGE_SIZE_SMALL);

    acquire_write(&vmo->lock);
    size_t old_size = vmo->size;

    if (aligned_new == old_size) {
        release_write(&vmo->lock);
        return ERR_OK;
    }

    if (aligned_new < old_size) {
        release_write(&vmo->lock);
        vm_object_truncate(vmo, aligned_new, old_size);
        return ERR_OK;
    }

    vmo->size = aligned_new;
    release_write(&vmo->lock);
    return ERR_OK;
}

int sys_vspace_protect(uint64_t vspace_cap, uintptr_t addr, size_t size, uint32_t new_prots) {
    process_t* proc = smp_current_core()->curr_thread->owner;

    struct vm_space* space = resolve_vspace(proc->root_cnode, vspace_cap, RIGHT_WRITE);
    if (!space) return ERR_DENIED;

    if (!is_aligned(addr, PAGE_SIZE_SMALL) || size == 0) return ERR_INVALID;

    uint32_t prot_flags = 0;
    if (new_prots & VSPACE_PROT_READ) prot_flags |= VMM_FLAG_READ;
    if (new_prots & VSPACE_PROT_WRITE) prot_flags |= VMM_FLAG_WRITE;
    if (new_prots & VSPACE_PROT_EXEC) prot_flags |= VMM_FLAG_EXECUTE;

    return vmprotect(space, addr, size, prot_flags);
}

#define min(a, b) ((a) > (b) ? (b) : (a))

static int
vmo_direct_io(uint64_t vmo_cap, void* buffer, size_t offset, size_t size, bool is_write) {
    if (unlikely(!buffer || size == 0)) return ERR_INVALID;

    struct process* proc = smp_current_core()->curr_thread->owner;
    uint16_t req_rights  = is_write ? RIGHT_WRITE : RIGHT_READ;

    vm_object_t* vmo = cap_resolve(proc->root_cnode, vmo_cap, req_rights, CAP_TYPE_VMO);
    if (unlikely(!vmo)) return ERR_DENIED;
    if (unlikely(offset + size > vmo->size)) return ERR_INVALID;

    size_t bytes_transferred = 0;
    while (bytes_transferred < size) {
        size_t curr_offset = offset + bytes_transferred;
        size_t page_base   = align_down(curr_offset, PAGE_SIZE_SMALL);
        size_t page_offset = curr_offset - page_base;
        size_t chunk_size  = min(PAGE_SIZE_SMALL - page_offset, size - bytes_transferred);

        uintptr_t phys = 0;

    retry_page:
        int status = vm_object_get_page(vmo, page_base, PAGE_SHIFT_SMALL, true, is_write, &phys);

        if (unlikely(status == ERR_AGAIN)) {
            struct vmo_page_waiter waiter;
            sched_prepare_page_wait(&waiter, vmo, page_base);

            status = vm_object_get_page(vmo, page_base, PAGE_SHIFT_SMALL, false, is_write, &phys);
            if (status == ERR_OK) {
                sched_abort_page_wait(&waiter);
            } else {
                uint32_t cluster   = vmo->read_ahead_cluster;
                size_t aligned_req = align_down(page_base, cluster);

                ipc_send_page_request(vmo->pager_port, vmo->pager_key, aligned_req, cluster);
                sched_commit_page_wait();

                goto retry_page;
            }
        } else if (unlikely(status != ERR_OK)) {
            return status;
        }

        void* kernel_ptr = (void*)(to_higher_half(phys) + page_offset);

        if (is_write) {
            if (unlikely(
                    copy_from_user(kernel_ptr, (uint8_t*)buffer + bytes_transferred, chunk_size) !=
                    0
                )) {
                return ERR_FAULT;
            }
        } else {
            if (unlikely(
                    copy_to_user((uint8_t*)buffer + bytes_transferred, kernel_ptr, chunk_size) != 0
                )) {
                return ERR_FAULT;
            }
        }

        bytes_transferred += chunk_size;
    }

    return ERR_OK;
}

int sys_vmo_read(uint64_t vmo_cap, void* buffer, size_t offset, size_t size) {
    return vmo_direct_io(vmo_cap, buffer, offset, size, false);
}

int sys_vmo_write(uint64_t vmo_cap, const void* buffer, size_t offset, size_t size) {
    return vmo_direct_io(vmo_cap, (void*)buffer, offset, size, true);
}

int sys_vmo_clone(
    uint64_t src_vmo_cap,
    size_t offset,
    size_t size,
    uint32_t,
    uint64_t* out_vmo_cap
) {
    process_t* proc = smp_current_core()->curr_thread->owner;
    if (unlikely(!proc || !out_vmo_cap)) return ERR_INVALID;

    vm_object_t* parent = cap_resolve(proc->root_cnode, src_vmo_cap, RIGHT_READ, CAP_TYPE_VMO);
    if (unlikely(!parent)) return ERR_DENIED;
    if (unlikely(offset > parent->size)) return ERR_INVALID;

    size_t clone_size = (size > 0) ? size : (parent->size - offset);

    if (unlikely(offset + clone_size > parent->size || offset + clone_size < offset))
        return ERR_INVALID;

    vm_object_t* shadow = vm_object_create_shadow(parent, offset, clone_size);
    if (unlikely(!shadow)) return ERR_NO_MEM;

    if (size > 0 && size < shadow->size) shadow->size = align_up(size, PAGE_SIZE_SMALL);

    uint64_t cap_id;
    struct capability* cap = cap_alloc(proc->root_cnode, &cap_id);
    if (unlikely(!cap)) {
        vm_object_deref(shadow);
        return ERR_CAP_EXHAUSTED;
    }

    acquire_qspinlock(&cap->lock);
    atomic_store_explicit(&cap->object_ptr, (uintptr_t)shadow, memory_order_release);
    cap->type   = CAP_TYPE_VMO;
    cap->rights = RIGHT_ALL;
    release_qspinlock(&cap->lock);

    if (unlikely(copy_to_user(out_vmo_cap, &cap_id, sizeof(uint64_t)) != 0)) {
        sys_cap_close(proc->root_cnode, cap_id);
        return ERR_FAULT;
    }

    return ERR_OK;
}