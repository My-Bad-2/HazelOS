#include "memory/vm_object.h"

#include <stdint.h>
#include <string.h>

#include "compiler.h"
#include "core/errors.h"
#include "core/syscalls.h"
#include "libs/kobject.h"
#include "libs/math.h"
#include "libs/xarray.h"
#include "memory/heap.h"
#include "memory/memory.h"
#include "memory/pmm.h"
#include "sched/wait.h"

static kmem_cache_t* vm_object_cache = nullptr;
// NOLINTNEXTLINE
uintptr_t global_zero_page_phys = 0;

static inline uint64_t pack_page(uintptr_t phys, uint32_t flags) {
    return (phys & ~0xffful) | (flags & 0xffful);
}

static inline uintptr_t unpack_phys(uint64_t val) {
    return val & ~0xffful;
}

static inline uint32_t unpack_flags(uint64_t val) {
    return val & 0xffful;
}

static void free_physical_frame(uintptr_t phys, uint32_t flags) {
    if (unlikely(phys == global_zero_page_phys)) return;

    size_t frames = 1;
    if (flags & PAGE_FLAG_1G)
        frames = PAGE_SIZE_LARGE / PAGE_SIZE_SMALL;
    else if (flags & PAGE_FLAG_2M)
        frames = PAGE_SIZE_MEDIUM / PAGE_SIZE_SMALL;

    for (size_t i = 0; i < frames; i++) pmm_dec_ref((void*)(phys + (i * PAGE_SIZE_SMALL)));
}

void vmo_release(struct kobject* kobj) {
    vm_object_t* obj = container_of(kobj, vm_object_t, kobj);

    if (obj->backing) vm_object_deref(obj->backing);

    uint64_t index;
    xa_entry_t entry;
    xa_for_each(&obj->page_tree, index, entry) {
        if (xa_is_value(entry)) {
            uint64_t val = xa_to_value(entry);
            free_physical_frame(unpack_phys(val), unpack_flags(val));
        }
    }

    xa_destroy(&obj->page_tree);
    kmem_cache_free(vm_object_cache, obj);
}

void vm_object_init(void) {
    vm_object_cache =
        kmem_cache_create("vm_object", sizeof(vm_object_t), _Alignof(vm_object_t), 0, nullptr);
    global_zero_page_phys = (uintptr_t)pmm_alloc(1);
    memset((void*)to_higher_half(global_zero_page_phys), 0, PAGE_SIZE_SMALL);
}

vm_object_t* vm_object_create(vmo_type_t type, size_t size) {
    vm_object_t* obj = (vm_object_t*)kmem_cache_alloc(vm_object_cache);
    if (!obj) return nullptr;

    create_rwlock(&obj->lock);
    kref_init(&obj->kobj, CAP_TYPE_VMO);

    obj->type               = type;
    obj->size               = align_up(size, PAGE_SIZE_SMALL);
    obj->backing            = nullptr;
    obj->pager_port         = nullptr;
    obj->pager_key          = 0;
    obj->read_ahead_cluster = PAGE_SIZE_SMALL;

    xa_init(&obj->page_tree, 6);
    return obj;
}

vm_object_t*
vm_object_create_pager(size_t size, struct ipc_port* port, uint64_t key, uint32_t cluster) {
    vm_object_t* obj = vm_object_create(VM_OBJ_PAGER, size);
    if (obj) {
        obj->pager_port = port;
        obj->pager_key  = key;
        obj->read_ahead_cluster =
            cluster > 0 ? align_up(cluster, PAGE_SIZE_SMALL) : PAGE_SIZE_SMALL;
    }

    return obj;
}

vm_object_t* vm_object_create_shadow(vm_object_t* parent_obj, size_t offset, size_t size) {
    if (!parent_obj) return nullptr;
    if (offset + size > parent_obj->size) return nullptr;

    vm_object_t* shadow = vm_object_create(VM_OBJ_SHADOW, size);
    if (shadow) {
        vm_object_ref(parent_obj);
        shadow->backing = parent_obj;
        // Snap the backing offset to page boundary
        shadow->backing_offset = align_down(offset, PAGE_SIZE_SMALL);
    }

    return shadow;
}

void vm_object_ref(vm_object_t* obj) {
    if (obj) kref_get(&obj->kobj);
}

void vm_object_deref(vm_object_t* obj) {
    if (obj) kref_put(&obj->kobj, vmo_release);
}

static int vmo_lookup(
    vm_object_t* obj,
    size_t offset,
    uint32_t* out_flags,
    uint64_t* out_idx,
    uintptr_t* out_phys
) {
    uint64_t idx_1g = align_down(offset, PAGE_SIZE_LARGE) >> PAGE_SHIFT_SMALL;
    uint64_t idx_2m = align_down(offset, PAGE_SIZE_MEDIUM) >> PAGE_SHIFT_SMALL;
    uint64_t idx_4k = offset >> PAGE_SHIFT_SMALL;

    xa_entry_t entry = xa_load(&obj->page_tree, idx_1g);
    if (entry && xa_is_value(entry)) {
        if (unpack_flags(xa_to_value(entry)) & PAGE_FLAG_1G) {
            *out_flags = unpack_flags(xa_to_value(entry));
            *out_idx   = idx_1g;
            *out_phys  = unpack_phys(xa_to_value(entry)) + (offset % (1ul << 30));
            return ERR_OK;
        }
    }

    entry = xa_load(&obj->page_tree, idx_2m);
    if (entry && xa_is_value(entry)) {
        if (unpack_flags(xa_to_value(entry)) & PAGE_FLAG_2M) {
            *out_flags = unpack_flags(xa_to_value(entry));
            *out_idx   = idx_2m;
            *out_phys  = unpack_phys(xa_to_value(entry)) + (offset % (1ul << 21));
            return ERR_OK;
        }
    }

    entry = xa_load(&obj->page_tree, idx_4k);
    if (entry && xa_is_value(entry)) {
        *out_flags = unpack_flags(xa_to_value(entry));
        *out_idx   = idx_4k;
        *out_phys  = unpack_phys(xa_to_value(entry));
        return ERR_OK;
    }

    return ERR_NO_ENT;
}

static int vmo_upgrade_dirty(vm_object_t* obj, uint64_t target_idx, uintptr_t* out_phys) {
    acquire_write(&obj->lock);

    xa_entry_t entry = xa_load(&obj->page_tree, target_idx);
    if (unlikely(!entry || !xa_is_value(entry))) {
        release_write(&obj->lock);
        return ERR_AGAIN;
    }

    uint64_t val           = xa_to_value(entry);
    uintptr_t current_phys = unpack_phys(val);
    uint32_t current_flags = unpack_flags(val);

    if (current_flags & PAGE_FLAG_DIRTY) {
        release_write(&obj->lock);
        *out_phys = current_phys;
        return ERR_OK;
    }

    if (current_phys == global_zero_page_phys) {
        void* new_phys = pmm_alloc(1);
        if (!new_phys) {
            release_write(&obj->lock);
            return ERR_NO_MEM;
        }

        memset((void*)to_higher_half((uintptr_t)new_phys), 0, PAGE_SIZE_SMALL);
        pmm_inc_ref(new_phys);

        uint64_t new_val = pack_page((uintptr_t)new_phys, PAGE_FLAG_DIRTY);
        xa_store(&obj->page_tree, target_idx, xa_mk_value(new_val));

        release_write(&obj->lock);
        *out_phys = (uintptr_t)new_phys;
        return ERR_OK;
    }

    uint64_t new_val = pack_page(current_phys, current_flags | PAGE_FLAG_DIRTY);
    xa_store(&obj->page_tree, target_idx, xa_mk_value(new_val));

    release_write(&obj->lock);
    *out_phys = current_phys;
    return ERR_OK;
}

static int vmo_allocate_anon(
    vm_object_t* obj,
    size_t offset,
    uint8_t page_shift,
    bool is_write,
    uintptr_t* out_phys
) {
    uint64_t target_idx = offset >> 12;
    uint32_t size_flag  = 0;
    size_t alloc_size   = PAGE_SIZE_SMALL;

    if (page_shift == PAGE_SHIFT_LARGE) {
        target_idx = align_down(offset, PAGE_SIZE_LARGE) >> PAGE_SHIFT_SMALL;
        size_flag  = PAGE_FLAG_1G;
        alloc_size = PAGE_SIZE_LARGE;
    } else if (page_shift == PAGE_SHIFT_MEDIUM) {
        target_idx = align_down(offset, PAGE_SIZE_MEDIUM) >> PAGE_SHIFT_SMALL;
        size_flag  = PAGE_FLAG_2M;
        alloc_size = PAGE_SIZE_MEDIUM;
    }

    size_t frames_needed = alloc_size >> 12;

    acquire_write(&obj->lock);

    // Collision Check
    for (size_t i = 0; i < frames_needed; i++) {
        if (xa_load(&obj->page_tree, target_idx + i) != nullptr) {
            release_write(&obj->lock);
            return ERR_EXIST;
        }
    }

    void* new_phys = pmm_alloc(frames_needed);
    if (!new_phys) {
        release_write(&obj->lock);
        return ERR_NO_MEM;
    }

    // Shadow Copy Data OR Zero out
    if (obj->type == VM_OBJ_SHADOW && obj->backing && alloc_size == PAGE_SIZE_SMALL) {
        uintptr_t orig_phys;
        int status = vm_object_get_page(
            obj->backing,
            offset + obj->backing_offset,
            page_shift,
            true,
            false,
            &orig_phys
        );

        if (status == ERR_OK && orig_phys != global_zero_page_phys)
            memcpy(
                (void*)to_higher_half((uintptr_t)new_phys),
                (void*)to_higher_half(orig_phys),
                PAGE_SIZE_SMALL
            );
        else
            memset((void*)to_higher_half((uintptr_t)new_phys), 0, PAGE_SIZE_SMALL);

    } else {
        memset((void*)to_higher_half((uintptr_t)new_phys), 0, alloc_size);
    }

    for (size_t i = 0; i < frames_needed; i++)
        pmm_inc_ref((void*)((uintptr_t)new_phys + (i * PAGE_SIZE_SMALL)));

    uint32_t new_flags  = (is_write ? PAGE_FLAG_DIRTY : 0) | size_flag;
    uint64_t packed_val = pack_page((uintptr_t)new_phys, new_flags);

    if (unlikely(xa_store(&obj->page_tree, target_idx, xa_mk_value(packed_val)) != XA_OK)) {
        free_physical_frame((uintptr_t)new_phys, new_flags);
        release_write(&obj->lock);
        return ERR_NO_MEM;
    }

    release_write(&obj->lock);
    *out_phys = (uintptr_t)new_phys;
    return ERR_OK;
}

int vm_object_get_page(
    vm_object_t* obj,
    size_t offset,
    uint8_t page_shift,
    bool alloc_on_miss,
    bool is_write,
    uintptr_t* out_phys
) {
    if (unlikely(!obj || offset >= obj->size || !out_phys)) return ERR_INVALID;

retry:
    acquire_read(&obj->lock);
    uint32_t flags      = 0;
    uint64_t target_idx = 0;
    uintptr_t phys      = 0;

    int status = vmo_lookup(obj, offset, &flags, &target_idx, &phys);
    release_read(&obj->lock);

    if (status == ERR_OK) {
        if (is_write && !(flags & PAGE_FLAG_DIRTY)) {
            status = vmo_upgrade_dirty(obj, target_idx, &phys);
            if (status == ERR_AGAIN) goto retry;
            if (status != ERR_OK) return status;
        }

        *out_phys = phys;
        return ERR_OK;
    }

    if (obj->type == VM_OBJ_PAGER) return ERR_AGAIN;

    if (obj->type == VM_OBJ_SHADOW && obj->backing && !is_write)
        return vm_object_get_page(
            obj->backing,
            offset + obj->backing_offset,
            page_shift,
            alloc_on_miss,
            false,
            out_phys
        );

    if (!alloc_on_miss) return ERR_NO_ENT;

    if (!is_write && obj->type == VM_OBJ_ANONYMOUS && page_shift == 12) {
        *out_phys = global_zero_page_phys;
        return ERR_OK;
    }

    status = vmo_allocate_anon(obj, offset, page_shift, is_write, &phys);
    if (status == ERR_EXIST) goto retry;
    if (status != ERR_OK) return status;

    *out_phys = phys;
    return ERR_OK;
}

int sys_vmo_supply_pages(
    struct cnode* root,
    uint64_t vmo_cap,
    size_t offset,
    void* user_data,
    size_t length
) {
    if (unlikely(!user_data || !is_aligned(offset, PAGE_SIZE_SMALL))) return ERR_INVALID;

    vm_object_t* vmo = cap_resolve(root, vmo_cap, RIGHT_PAGER_SUPPLY, CAP_TYPE_VMO);
    if (!vmo) return ERR_DENIED;
    if (vmo->type != VM_OBJ_PAGER) return ERR_INVALID;

    size_t aligned_length = align_up(length, PAGE_SIZE_SMALL);

    for (size_t i = 0; i < aligned_length; i += PAGE_SIZE_SMALL) {
        uint64_t page_index = (offset + i) / PAGE_SIZE_SMALL;

        acquire_read(&vmo->lock);
        bool exists = (xa_load(&vmo->page_tree, page_index) != nullptr);
        release_read(&vmo->lock);

        if (exists) continue;

        void* phys_frame = pmm_alloc(1);
        if (!phys_frame) return ERR_NO_MEM;

        if (!copy_from_user(
                (void*)to_higher_half((uintptr_t)phys_frame),
                (uint8_t*)user_data + i,
                PAGE_SIZE_SMALL
            )) {
            pmm_free(phys_frame);
            return ERR_FAULT;
        }

        pmm_inc_ref(phys_frame);
        acquire_write(&vmo->lock);

        if (xa_load(&vmo->page_tree, page_index) != nullptr) {
            pmm_dec_ref(phys_frame);
        } else {
            uint64_t packed_val = pack_page((uintptr_t)phys_frame, 0);
            if (xa_store(&vmo->page_tree, page_index, xa_mk_value(packed_val)) != XA_OK) {
                pmm_dec_ref(phys_frame);
                release_write(&vmo->lock);
                return ERR_NO_MEM;
            }
        }

        release_write(&vmo->lock);
    }

    sched_wake_threads_waiting_on_page(vmo, offset, aligned_length);
    return ERR_OK;
}

void vm_object_truncate(vm_object_t* obj, size_t start_offset, size_t end_offset) {
    if (!obj || start_offset >= end_offset) return;

    uint64_t start_idx = start_offset / PAGE_SIZE_SMALL;
    uint64_t end_idx   = align_up(end_offset, PAGE_SIZE_SMALL) / PAGE_SIZE_SMALL;

    acquire_write(&obj->lock);

    xa_cursor_t cursor;
    xa_entry_t entry;

    xa_for_each_cursor(&cursor, &obj->page_tree, start_idx, entry) {
        if (cursor.index >= end_idx) break;

        if (xa_is_value(entry)) {
            uint64_t val = xa_to_value(entry);
            free_physical_frame(unpack_phys(val), unpack_flags(val));
            xa_erase(&obj->page_tree, cursor.index);
        }
    }

    if (end_offset >= obj->size && start_offset < obj->size) obj->size = start_offset;
    release_write(&obj->lock);
}

void vm_object_collapse(vm_object_t* obj) {
    if (!obj || obj->type != VM_OBJ_SHADOW) return;

    acquire_write(&obj->lock);
    vm_object_t* backing = obj->backing;

    if (backing && atomic_load_explicit(&backing->kobj.ref_count, memory_order_acquire) == 1) {
        acquire_write(&backing->lock);

        uint64_t index;
        xa_entry_t entry;

        uint64_t offset_pages = obj->backing_offset / PAGE_SIZE_SMALL;
        uint64_t child_pages  = obj->size / PAGE_SIZE_SMALL;

        xa_for_each(&backing->page_tree, index, entry) {
            if (xa_is_value(entry)) {
                uint64_t val   = xa_to_value(entry);
                uintptr_t phys = unpack_phys(val);
                uint32_t flags = unpack_flags(val);

                // Is the parent's page outside the child's offset window?
                if (index < offset_pages || index >= (offset_pages + child_pages))
                    free_physical_frame(phys, flags);

                uint64_t child_idx = index - offset_pages;

                if (!xa_load(&obj->page_tree, child_idx)) {
                    if (xa_store(&obj->page_tree, child_idx, entry) != XA_OK)
                        free_physical_frame(phys, flags);
                } else {
                    free_physical_frame(phys, flags);
                }
            }
        }

        vm_object_t* grandparent = backing->backing;
        obj->backing             = grandparent;
        if (grandparent) {
            obj->backing_offset += backing->backing_offset;
            vm_object_ref(grandparent);
        } else {
            obj->backing_offset = 0;
        }

        release_write(&backing->lock);

        backing->backing = nullptr;
        xa_destroy(&backing->page_tree);
        kmem_cache_free(vm_object_cache, backing);
    }

    release_write(&obj->lock);
}

int vm_object_pin_page(vm_object_t* obj, size_t offset, bool pin) {
    if (unlikely(!obj || offset >= obj->size)) return ERR_INVALID;

    uint64_t page_index = offset / PAGE_SIZE_SMALL;
    int status          = ERR_NO_ENT;

    acquire_write(&obj->lock);

    xa_entry_t entry = xa_load(&obj->page_tree, page_index);
    if (likely(entry && xa_is_value(entry))) {
        uint64_t val   = xa_to_value(entry);
        uint32_t flags = unpack_flags(val);
        uintptr_t phys = unpack_phys(val);

        if (pin)
            flags |= PAGE_FLAG_PINNED;
        else
            flags &= ~PAGE_FLAG_PINNED;

        uint64_t new_val = pack_page(phys, flags);
        xa_store(&obj->page_tree, page_index, xa_mk_value(new_val));
        status = ERR_OK;
    }

    release_write(&obj->lock);
    return status;
}