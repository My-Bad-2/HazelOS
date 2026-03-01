#include "memory/vm_object.h"

#include <string.h>

#include "libs/math.h"
#include "memory/heap.h"
#include "memory/memory.h"
#include "memory/pmm.h"

static kmem_cache_t* vm_object_cache = nullptr;

static inline uint64_t pack_page_val(uintptr_t phys, uint32_t flags) {
    return (phys & ~0xFFFul) | (flags & 0xFFFul);
}

static inline uintptr_t unpack_phys(uint64_t val) {
    return val & ~0xFFFul;
}

static inline uint32_t unpack_flags(uint64_t val) {
    return val & 0xFFFul;
}

void vm_object_init(void) {
    vm_object_cache =
        kmem_cache_create("vm_object", sizeof(vm_object_t), _Alignof(vm_object_t), 0, nullptr);
}

vm_object_t* vm_object_create(vm_object_type_t type, size_t size) {
    vm_object_t* obj = (vm_object_t*)kmem_cache_alloc(vm_object_cache);
    if (!obj) {
        return nullptr;
    }

    create_rwlock(&obj->lock);
    atomic_init(&obj->ref_count, 1);

    obj->type    = type;
    obj->size    = align_up(size, PAGE_SIZE_SMALL);
    obj->vnode   = nullptr;
    obj->backing = nullptr;

    xa_init(&obj->pages, 6);  // 2^6 = 64 slots per node

    return obj;
}

void vm_object_ref(vm_object_t* obj) {
    if (obj) {
        atomic_fetch_add_explicit(&obj->ref_count, 1, memory_order_relaxed);
    }
}

void vm_object_deref(vm_object_t* obj) {
    if (!obj) {
        return;
    }

    if (atomic_fetch_sub_explicit(&obj->ref_count, 1, memory_order_acq_rel) == 1) {
        if (obj->backing) {
            vm_object_deref(obj->backing);
        }

        uint64_t index;
        xa_entry_t entry;

        xa_for_each(&obj->pages, index, entry) {
            if (xa_is_value(entry)) {
                uintptr_t phys = unpack_phys(xa_to_value(entry));

                pmm_dec_ref((void*)phys);
            }
        }

        xa_destroy(&obj->pages);
        kmem_cache_free(vm_object_cache, obj);
    }
}

vm_object_t* vm_object_create_shadow(vm_object_t* parent_obj) {
    if (!parent_obj) {
        return nullptr;
    }

    vm_object_t* shadow = vm_object_create(VM_OBJ_SHADOW, parent_obj->size);
    if (!shadow) {
        return nullptr;
    }

    vm_object_ref(parent_obj);
    shadow->backing = parent_obj;

    return shadow;
}

void vm_object_collapse(vm_object_t* obj) {
    if (!obj || obj->type != VM_OBJ_SHADOW) {
        return;
    }

    acquire_write(&obj->lock);

    vm_object_t* backing = obj->backing;

    if (backing && atomic_load_explicit(&backing->ref_count, memory_order_acquire) == 1) {
        acquire_write(&backing->lock);

        uint64_t index;
        xa_entry_t entry;

        xa_for_each(&backing->pages, index, entry) {
            if (xa_is_value(entry)) {
                if (!xa_load(&obj->pages, index)) {
                    xa_store(&obj->pages, index, entry);
                } else {
                    uintptr_t phys = unpack_phys(xa_to_value(entry));

                    pmm_dec_ref((void*)phys);
                }
            }
        }

        vm_object_t* grandparent = backing->backing;
        obj->backing             = grandparent;

        if (grandparent) {
            vm_object_ref(grandparent);
        }

        release_write(&backing->lock);

        backing->backing = nullptr;
        xa_destroy(&backing->pages);
        kmem_cache_free(vm_object_cache, backing);
    }

    release_write(&obj->lock);
}

void vm_object_truncate(vm_object_t* obj, size_t start_offset, size_t end_offset) {
    if (!obj || start_offset >= end_offset) {
        return;
    }

    uint64_t start_idx = start_offset / PAGE_SIZE_SMALL;
    uint64_t end_idx   = align_up(end_offset, PAGE_SIZE_SMALL) / PAGE_SIZE_SMALL;

    acquire_write(&obj->lock);

    xa_cursor_t cursor;
    xa_entry_t entry;

    xa_for_each_cursor(&cursor, &obj->pages, start_idx, entry) {
        if (cursor.index >= end_idx) {
            break;
        }

        if (xa_is_value(entry)) {
            uintptr_t phys = unpack_phys(xa_to_value(entry));

            pmm_dec_ref((void*)phys);
            xa_erase(&obj->pages, cursor.index);
        }
    }

    if (end_offset >= obj->size && start_offset < obj->size) {
        obj->size = start_offset;
    }

    release_write(&obj->lock);
}

bool vm_object_pin_page(vm_object_t* obj, size_t offset, bool pin) {
    if (!obj || offset >= obj->size) {
        return false;
    }

    uint64_t page_index = offset / PAGE_SIZE_SMALL;
    bool success        = false;

    acquire_write(&obj->lock);

    xa_entry_t entry = xa_load(&obj->pages, page_index);
    if (entry && xa_is_value(entry)) {
        uint64_t val   = xa_to_value(entry);
        uint32_t flags = unpack_flags(val);
        uintptr_t phys = unpack_phys(val);

        if (pin) {
            flags |= PAGE_FLAG_PINNED;
        } else {
            flags &= ~PAGE_FLAG_PINNED;
        }

        uint64_t new_val = pack_page_val(phys, flags);
        xa_store(&obj->pages, page_index, xa_mk_value(new_val));
        success = true;
    }

    release_write(&obj->lock);
    return success;
}

uintptr_t
vm_object_get_page(vm_object_t* obj, size_t offset, bool allocate_on_miss, bool is_write) {
    if (!obj || offset >= obj->size) {
        return 0;
    }

    uint64_t page_index = offset / PAGE_SIZE_SMALL;

    acquire_read(&obj->lock);

    xa_entry_t entry = xa_load(&obj->pages, page_index);

    if (entry && xa_is_value(entry)) {
        uint64_t val   = xa_to_value(entry);
        uintptr_t phys = unpack_phys(val);
        uint32_t flags = unpack_flags(val);

        if (is_write && !(flags & PAGE_FLAG_DIRTY)) {
            release_read(&obj->lock);
            acquire_write(&obj->lock);

            entry = xa_load(&obj->pages, page_index);
            if (entry && xa_is_value(entry)) {
                val                = xa_to_value(entry);
                uint32_t new_flags = unpack_flags(val) | PAGE_FLAG_DIRTY;
                uint64_t new_val   = pack_page_val(unpack_phys(val), new_flags);

                xa_store(&obj->pages, page_index, xa_mk_value(new_val));
                phys = unpack_phys(val);
            }

            release_write(&obj->lock);
            return phys;
        }

        release_read(&obj->lock);
        return phys;
    }

    if (obj->type == VM_OBJ_SHADOW && obj->backing) {
        if (!is_write) {
            uintptr_t backing_phys =
                vm_object_get_page(obj->backing, offset, allocate_on_miss, false);

            release_read(&obj->lock);
            return backing_phys;
        }
    }

    release_read(&obj->lock);

    if (!allocate_on_miss) {
        return 0;
    }

    acquire_write(&obj->lock);

    entry = xa_load(&obj->pages, page_index);
    if (entry && xa_is_value(entry)) {
        uintptr_t phys = unpack_phys(xa_to_value(entry));
        release_write(&obj->lock);
        return phys;
    }

    void* new_phys = pmm_alloc(1);
    if (!new_phys) {
        release_write(&obj->lock);
        return 0;
    }

    if (obj->type == VM_OBJ_SHADOW && obj->backing) {
        uintptr_t orig_phys = vm_object_get_page(obj->backing, offset, true, false);
        if (orig_phys) {
            memcpy(
                (void*)to_higher_half((uintptr_t)new_phys),
                (void*)to_higher_half(orig_phys),
                PAGE_SIZE_SMALL
            );
        } else {
            memset((void*)to_higher_half((uintptr_t)new_phys), 0, PAGE_SIZE_SMALL);
        }
    } else if (obj->type == VM_OBJ_FILE && obj->vnode) {
        // TODO: VFS READ Operation
    } else {
        memset((void*)to_higher_half((uintptr_t)new_phys), 0, PAGE_SIZE_SMALL);
    }

    pmm_inc_ref(new_phys);

    uint32_t new_flags  = is_write ? PAGE_FLAG_DIRTY : 0;
    uint64_t packed_val = pack_page_val((uintptr_t)new_phys, new_flags);

    if (xa_store(&obj->pages, page_index, xa_mk_value(packed_val)) != XA_OK) {
        pmm_dec_ref(new_phys);
        pmm_free(new_phys);

        release_write(&obj->lock);
        return 0;
    }

    release_write(&obj->lock);
    return (uintptr_t)new_phys;
}