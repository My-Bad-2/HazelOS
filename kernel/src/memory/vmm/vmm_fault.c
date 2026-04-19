#include <stdint.h>
#include <string.h>

#include "compiler.h"
#include "core/errors.h"
#include "libs/log.h"
#include "libs/math.h"
#include "memory/memory.h"
#include "memory/vm_object.h"
#include "memory/vma.h"
#include "sched/wait.h"

#include "../internal/vma_tree.h"

extern uintptr_t global_zero_page_phys;

static inline bool vmm_check_permissions(struct vm_area* vma, struct vmm_fault_info info) {
    if (unlikely(vma->flags & VMM_FLAG_GUARD)) return false;
    if (unlikely(info.is_user && !(vma->flags & VMM_FLAG_USER))) return false;
    if (unlikely(info.is_exec && !(vma->flags & VMM_FLAG_EXECUTE))) return false;
    if (unlikely(info.is_write && !(vma->flags & VMM_FLAG_WRITE))) return false;
    return true;
}

static inline bool vmm_map_resolved_page(
    struct vm_space* space,
    struct vm_area* vma,
    uintptr_t aligned_addr,
    uintptr_t phys,
    size_t map_page_size,
    bool is_write
) {
    uint32_t pte_flags = vma->flags;

    if (unlikely((vma->flags & VMM_FLAG_COW) && !is_write)) pte_flags &= ~VMM_FLAG_WRITE;
    if (unlikely(phys == global_zero_page_phys)) pte_flags &= ~VMM_FLAG_WRITE;

    uint32_t hw_flags = pte_flags & (VMM_FLAG_READ | VMM_FLAG_WRITE | VMM_FLAG_EXECUTE |
                                     VMM_FLAG_USER | VMM_FLAG_GLOBAL);

    pagemap_unmap_args_t unmap_args = {
        .virt_addr = (void*)aligned_addr,
        .length    = map_page_size,
        .free_phys = false,
    };

    pagemap_unmap(space->map, &unmap_args);

    pagemap_map_args_t args = {
        .virt_addr = (void*)aligned_addr,
        .phys_addr = (void*)phys,
        .length    = map_page_size,
        .flags     = hw_flags,
        .cache     = vma->cache,
        .page_size = map_page_size,
    };

    return pagemap_map(space->map, &args);
}

static bool vmm_handle_pager_fault(struct vm_area* vma, size_t object_offset, bool is_write) {
    struct vmo_page_waiter waiter;
    sched_prepare_page_wait(&waiter, vma->object, object_offset);

    uintptr_t phys;
    int status =
        vm_object_get_page(vma->object, object_offset, vma->page_shift, false, is_write, &phys);

    if (status == ERR_OK) {
        sched_abort_page_wait(&waiter);
        return true;
    }

    uint32_t cluster      = vma->object->read_ahead_cluster;
    size_t aligned_offset = align_down(object_offset, cluster);

    ipc_send_page_request(vma->object->pager_port, vma->object->pager_key, aligned_offset, cluster);
    sched_commit_page_wait();

    return true;
}

bool vmm_handle_fault(struct vm_space* space, uintptr_t fault_addr, uint32_t error_code) {
    struct vmm_fault_info info = arch_decode_fault_error(error_code);

    acquire_read(&space->lock);

    struct vm_area* vma = atomic_load_explicit(&space->cached_vma, memory_order_acquire);
    if (unlikely(!vma || fault_addr < vma->start || fault_addr >= vma->end)) {
        vma = vmm_find_vma_unsafe(space, fault_addr);
        if (likely(vma)) atomic_store_explicit(&space->cached_vma, vma, memory_order_relaxed);
    }

    if (unlikely(!vma || !space->map || !vmm_check_permissions(vma, info))) {
        release_read(&space->lock);
        return false;
    }

    uintptr_t map_page_size = vma_page_size(vma);
    uintptr_t aligned_addr  = align_down(fault_addr, map_page_size);
    size_t object_offset    = vma->object_offset + (aligned_addr - vma->start);

    uintptr_t phys = 0;
    int status     = ERR_NO_ENT;

    // Transparent Huge Page Promotion Attempt
    uintptr_t huge_vaddr = align_down(fault_addr, PAGE_SIZE_MEDIUM);
    size_t huge_offset   = vma->object_offset + (huge_vaddr - vma->start);

    if (vma->page_shift == PAGE_SHIFT_SMALL && vma->object &&
        vma->object->type == VM_OBJ_ANONYMOUS && huge_vaddr >= vma->start &&
        (huge_vaddr + PAGE_SIZE_MEDIUM) <= vma->end) {
        status = vm_object_get_page(
            vma->object,
            huge_offset,
            PAGE_SHIFT_MEDIUM,
            true,
            info.is_write,
            &phys
        );

        if (status == ERR_OK) {
            aligned_addr  = huge_vaddr;
            map_page_size = PAGE_SIZE_MEDIUM;
        }
    }

    if (status != ERR_OK)
        status = vm_object_get_page(
            vma->object,
            object_offset,
            vma->page_shift,
            true,
            info.is_write,
            &phys
        );

    if (unlikely(status != ERR_OK)) {
        if (status == ERR_AGAIN) {
            release_read(&space->lock);
            return vmm_handle_pager_fault(vma, object_offset, info.is_write);
        }

        KLOG_ERROR("VMM: Failed to resolve page fault at %p. Status: %d", fault_addr, status);
        release_read(&space->lock);
        return false;
    }

    bool mapped =
        vmm_map_resolved_page(space, vma, aligned_addr, phys, map_page_size, info.is_write);

    if (unlikely(!mapped)) {
        release_read(&space->lock);
        KLOG_DEBUG("Not mapped!\n");
        return false;
    }

    if (unlikely(vma->object && vma->object->type == VM_OBJ_SHADOW))
        vm_object_collapse(vma->object);

    release_read(&space->lock);
    return true;
}