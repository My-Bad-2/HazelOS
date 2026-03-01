#include "memory/vma.h"

#include <stdatomic.h>
#include <string.h>

#include "libs/log.h"
#include "libs/math.h"
#include "libs/spinlock.h"
#include "memory/heap.h"
#include "memory/memory.h"
#include "memory/pagemap.h"
#include "memory/pmm.h"
#include "memory/vm_object.h"

#include "../internal/vma_tree.h"

#define max(a, b) ((a) > (b) ? (a) : (b))
#define min(a, b) ((a) < (b) ? (a) : (b))

static vm_space_t kspace;
vm_space_t* kernel_space = &kspace;
kmem_cache_t* vma_cache  = nullptr;

void vma_cache_init(void) {
    vma_cache = kmem_cache_create("vma_cache", sizeof(vm_area_t), _Alignof(vm_area_t), 0, nullptr);
    vm_object_init();
}

void vmm_init_space(vm_space_t* space, pagemap_t* map, uintptr_t start, uintptr_t end) {
    memset(space, 0, sizeof(vm_space_t));

    space->rb_root         = RB_ROOT;
    space->map             = map;
    space->start_limit     = start;
    space->end_limit       = end;
    space->allocation_hint = start;

    atomic_init(&space->cached_vma, nullptr);
    create_rwlock(&space->lock);
}

static size_t select_page_size(size_t size, uintptr_t addr) {
    if (size >= PAGE_SIZE_LARGE && (size % PAGE_SIZE_LARGE == 0) && (addr % PAGE_SIZE_LARGE == 0)) {
        return PAGE_SIZE_LARGE;
    }

    if (size >= PAGE_SIZE_MEDIUM && (size % PAGE_SIZE_MEDIUM == 0) &&
        (addr % PAGE_SIZE_MEDIUM == 0)) {
        return PAGE_SIZE_MEDIUM;
    }

    return PAGE_SIZE_SMALL;
}

static void
vmm_unmap_hardware_range(vm_space_t* space, uintptr_t start, size_t size, size_t page_size) {
    uintptr_t addr = start;
    uintptr_t end  = start + size;

    while (addr < end) {
        uintptr_t phys = pagemap_translate(space->map, addr);

        if (phys) {
            pagemap_unmap_args_t args = {
                .virt_addr = (void*)addr,
                .length    = page_size,
                .free_phys = false,
            };

            pagemap_unmap(space->map, &args);
        }

        addr += page_size;
    }
}

bool vmm_populate_vma_range(vm_space_t* space, vm_area_t* vma, uintptr_t start, size_t size) {
    if (vma->flags & VMM_FLAG_GUARD) return true;
    if ((vma->flags & VMM_FLAG_DEMAND) && !(vma->flags & VMM_FLAG_POPULATE)) return true;

    uintptr_t addr = start;
    uintptr_t end  = start + size;

    uint32_t pte_flags = vma->flags;

    if (vma->flags & VMM_FLAG_COW) {
        pte_flags &= ~VMM_FLAG_WRITE;
    }

    cache_type_t cache = (vma->flags & VMM_FLAG_MMIO) ? CACHE_UNCACHEABLE : vma->cache;

    while (addr < end) {
        size_t object_offset = vma->object_offset + (addr - vma->start);
        uintptr_t phys       = vm_object_get_page(vma->object, object_offset, true, false);

        if (!phys) {
            if (addr > start) {
                vmm_unmap_hardware_range(space, start, addr - start, vma->page_size);
            }

            return false;
        }

        pagemap_map_args_t args = {
            .virt_addr = (void*)addr,
            .phys_addr = (void*)phys,
            .length    = vma->page_size,
            .flags     = pte_flags,
            .cache     = cache,
            .page_size = vma->page_size,
        };

        if (!pagemap_map(space->map, &args)) {
            if (addr > start) {
                vmm_unmap_hardware_range(space, start, addr - start, vma->page_size);
            }

            return false;
        }

        addr += vma->page_size;
    }

    return true;
}

void* vmalloc(
    vm_space_t* space,
    void* hint_addr,
    size_t size,
    uint32_t flags,
    cache_type_t cache,
    size_t alignment
) {
    if (size == 0) {
        return nullptr;
    }

    alignment = max(alignment, PAGE_SIZE_SMALL);
    size      = align_up(size, PAGE_SIZE_SMALL);

    bool is_fixed = (flags & VMM_FLAG_FIXED) || (flags & VMM_FLAG_FIXED_NOREPLACE);
    if (is_fixed && !hint_addr) {
        KLOG_WARN("VMM: VMM_FLAG_FIXED requested but no hint_addr provided");
        return nullptr;
    }

    bool is_stack      = (flags & VMM_FLAG_STACK);
    size_t actual_size = size + (is_stack ? PAGE_SIZE_SMALL : 0);

    uintptr_t addr  = (uintptr_t)hint_addr;
    size_t final_ps = (hint_addr) ? select_page_size(size, addr) : select_page_size(size, 0);
    size_t align    = max(final_ps, alignment);

    if (is_fixed && (!is_aligned(addr, alignment) || addr < space->start_limit ||
                     addr + actual_size > space->end_limit)) {
        return nullptr;
    }

    acquire_write(&space->lock);

    vm_area_t* allocated_vma   = kmem_cache_alloc(vma_cache);
    vm_area_t* allocated_guard = is_stack ? kmem_cache_alloc(vma_cache) : nullptr;

    if (!allocated_vma || (is_stack && !allocated_guard)) {
        if (allocated_vma) {
            kmem_cache_free(vma_cache, allocated_vma);
        }

        if (allocated_guard) {
            kmem_cache_free(vma_cache, allocated_guard);
        }

        release_write(&space->lock);
        return nullptr;
    }

    memset(allocated_vma, 0, sizeof(vm_area_t));
    if (allocated_guard) {
        memset(allocated_guard, 0, sizeof(vm_area_t));
    }

    bool found = false;
    if (hint_addr) {
        struct rb_node* node = space->rb_root.rb_node;
        bool collision       = false;

        while (node) {
            vm_area_t* curr = rb_entry(node, vm_area_t, rb_node);
            if (addr < curr->end && curr->start < (addr + actual_size)) {
                collision = true;
                break;
            }

            node = (addr < curr->start) ? node->rb_left : node->rb_right;
        }

        if (collision) {
            if (is_fixed) {
                release_write(&space->lock);
                return nullptr;
            }
        } else {
            found = true;
        }
    }

    if (!found) {
        if (is_stack) {
            found = vmm_find_gap_top_down(space, actual_size, align, &addr);

            if (!found && align > PAGE_SIZE_SMALL) {
                final_ps = PAGE_SIZE_SMALL;
                found    = vmm_find_gap_top_down(space, actual_size, final_ps, &addr);
            }
        } else {
            found = vmm_find_gap_bottom_up(space, actual_size, align, &addr);

            if (!found && align > PAGE_SIZE_SMALL) {
                final_ps = PAGE_SIZE_SMALL;
                found    = vmm_find_gap_bottom_up(space, actual_size, final_ps, &addr);
            }
        }
    }

    if (!found) {
        KLOG_WARN("VMM: Out of virtual memory for space");
        kmem_cache_free(vma_cache, allocated_vma);

        if (allocated_guard) {
            kmem_cache_free(vma_cache, allocated_guard);
        }

        release_write(&space->lock);
        return nullptr;
    }

    uintptr_t map_start   = is_stack ? addr + PAGE_SIZE_SMALL : addr;
    uint32_t map_flags    = is_stack ? (flags & ~VMM_FLAG_STACK) : flags;
    vm_area_t* target_vma = is_stack ? allocated_guard : allocated_vma;

    target_vma->start     = map_start;
    target_vma->end       = map_start + size;
    target_vma->size      = size;
    target_vma->page_size = final_ps;
    target_vma->flags     = map_flags;
    target_vma->cache     = cache;

    target_vma->object        = vm_object_create(VM_OBJ_ANONYMOUS, size);
    target_vma->object_offset = 0;

    if (!target_vma->object) {
        kmem_cache_free(vma_cache, allocated_vma);

        if (allocated_guard) {
            kmem_cache_free(vma_cache, allocated_guard);
        }

        release_write(&space->lock);
        return nullptr;
    }

    if (!vmm_populate_vma_range(space, target_vma, map_start, size)) {
        KLOG_ERROR("VMM: Failed to map memory at %p", (void*)map_start);
        vm_object_deref(target_vma->object);
        kmem_cache_free(vma_cache, allocated_vma);

        if (allocated_guard) {
            kmem_cache_free(vma_cache, allocated_guard);
        }

        release_write(&space->lock);
        return nullptr;
    }

    if (!is_stack &&
        vmm_try_merge(space, addr, actual_size, flags, cache, final_ps, target_vma->object, 0)) {
        kmem_cache_free(vma_cache, allocated_vma);

        release_write(&space->lock);
        return (void*)addr;
    }

    if (is_stack) {
        allocated_vma->start     = addr;
        allocated_vma->end       = addr + PAGE_SIZE_SMALL;
        allocated_vma->size      = PAGE_SIZE_SMALL;
        allocated_vma->page_size = PAGE_SIZE_SMALL;
        allocated_vma->flags     = VMM_FLAG_GUARD;
        allocated_vma->cache     = CACHE_WRITE_BACK;
        allocated_vma->object    = nullptr;

        vmm_insert_vma(space, allocated_vma);
        vmm_insert_vma(space, allocated_guard);
        atomic_store_explicit(&space->cached_vma, allocated_guard, memory_order_relaxed);

        release_write(&space->lock);
        return (void*)allocated_guard->start;
    } else {
        vmm_insert_vma(space, allocated_vma);
        space->allocation_hint = allocated_vma->end;
        atomic_store_explicit(&space->cached_vma, allocated_vma, memory_order_relaxed);

        release_write(&space->lock);
        return (void*)addr;
    }
}

void vmfree(vm_space_t* space, void* ptr, size_t size) {
    uintptr_t start = (uintptr_t)ptr;
    uintptr_t end   = start + size;

    if (size == 0) {
        return;
    }

    acquire_write(&space->lock);

    while (start < end) {
        vm_area_t* vma = vmm_find_vma_unsafe(space, start);

        if (!vma) {
            struct rb_node* node = space->rb_root.rb_node;
            vm_area_t* next      = nullptr;

            while (node) {
                vm_area_t* curr = rb_entry(node, vm_area_t, rb_node);

                if (curr->start > start) {
                    next = curr;
                    node = node->rb_left;
                } else {
                    node = node->rb_right;
                }
            }

            if (!next || next->start >= end) {
                break;
            }
            vma = next;
        }

        uintptr_t unmap_start = max(start, vma->start);
        uintptr_t unmap_end   = min(end, vma->end);
        size_t unmap_size     = unmap_end - unmap_start;

        vmm_unmap_hardware_range(space, unmap_start, unmap_size, vma->page_size);

        if (unmap_start == vma->start && unmap_end == vma->end) {
            // Case 1: Full VMA Removal
            if (vma->flags & VMM_FLAG_STACK) {
                struct rb_node* prev = rb_prev(&vma->rb_node);
                if (prev) {
                    vm_area_t* guard = rb_entry(prev, vm_area_t, rb_node);
                    if (guard->flags == VMM_FLAG_GUARD && guard->end == vma->start) {
                        rb_erase_augmented(
                            &guard->rb_node,
                            &space->rb_root,
                            vma_compute_subtree_gap
                        );
                        kmem_cache_free(vma_cache, guard);
                    }
                }
            }

            rb_erase_augmented(&vma->rb_node, &space->rb_root, vma_compute_subtree_gap);

            if (vma->object) {
                vm_object_deref(vma->object);
            }

            kmem_cache_free(vma_cache, vma);
        } else if (unmap_start == vma->start) {
            // Case 2: Head Cut (Erase and re-insert due to changed start key)
            rb_erase_augmented(&vma->rb_node, &space->rb_root, vma_compute_subtree_gap);

            if (vma->object) {
                vma->object_offset += (unmap_end - vma->start);
            }

            vma->start = unmap_end;
            vma->size  = vma->end - vma->start;
            vmm_insert_vma(space, vma);
        } else if (unmap_end == vma->end) {
            // Case 3: Tail Cut (Shrink from the right)
            vma->end  = unmap_start;
            vma->size = vma->end - vma->start;

            struct rb_node* next = rb_next(&vma->rb_node);
            if (next) {
                vm_area_t* next_vma = rb_entry(next, vm_area_t, rb_node);
                next_vma->own_gap   = next_vma->start - vma->end;
                vma_propagate_gap_up(&next_vma->rb_node);
            }

            vma_propagate_gap_up(&vma->rb_node);
        } else {
            // Case 4: Middle Punch (Split into two VMAs)
            vm_area_t* right_half = vmm_split_vma(space, vma, unmap_end);

            if (right_half) {
                vma->end  = unmap_start;
                vma->size = vma->end - vma->start;

                right_half->own_gap = right_half->start - vma->end;

                vma_propagate_gap_up(&right_half->rb_node);
                vma_propagate_gap_up(&vma->rb_node);
            } else {
                KLOG_ERROR("VMM: Failed to split VMA during partial free at %p", (void*)unmap_end);
            }
        }

        start = unmap_end;
    }

    atomic_store_explicit(&space->cached_vma, nullptr, memory_order_relaxed);
    release_write(&space->lock);
}

void vmm_destroy_space(vm_space_t* space) {
    if (!space) {
        return;
    }

    acquire_write(&space->lock);

    struct rb_node* node = rb_first(&space->rb_root);

    while (node) {
        vm_area_t* vma       = rb_entry(node, vm_area_t, rb_node);
        struct rb_node* next = rb_next(node);
        uintptr_t addr       = vma->start;

        vmm_unmap_hardware_range(space, vma->start, vma->size, vma->page_size);
        rb_erase_augmented(&vma->rb_node, &space->rb_root, vma_compute_subtree_gap);
        kmem_cache_free(vma_cache, vma);

        node = next;
    }

    atomic_store_explicit(&space->cached_vma, nullptr, memory_order_relaxed);
    space->rb_root = RB_ROOT;

    release_write(&space->lock);
}

bool vmm_clone_space(vm_space_t* parent, vm_space_t* child) {
    if (!parent || !child) return false;

    acquire_read(&parent->lock);
    acquire_write(&child->lock);

    struct rb_node* node = rb_first(&parent->rb_root);

    while (node) {
        vm_area_t* parent_vma = rb_entry(node, vm_area_t, rb_node);
        vm_area_t* child_vma  = kmem_cache_alloc(vma_cache);

        if (!child_vma) {
            KLOG_ERROR("VMM: OOM allocating child VMA at %p", (void*)parent_vma->start);
            goto clone_fail;
        }

        memset(child_vma, 0, sizeof(vm_area_t));

        child_vma->start     = parent_vma->start;
        child_vma->end       = parent_vma->end;
        child_vma->size      = parent_vma->size;
        child_vma->page_size = parent_vma->page_size;
        child_vma->cache     = parent_vma->cache;
        child_vma->flags     = parent_vma->flags;

        bool is_cow =
            !(parent_vma->flags & VMM_FLAG_SHARED) && (parent_vma->flags & VMM_FLAG_WRITE);

        if (is_cow) {
            parent_vma->flags |= VMM_FLAG_COW;
            child_vma->flags |= VMM_FLAG_COW;

            child_vma->object        = vm_object_create_shadow(parent_vma->object);
            child_vma->object_offset = parent_vma->object_offset;

            if (!child_vma->object) {
                goto clone_fail;
            }
        } else {
            child_vma->object        = parent_vma->object;
            child_vma->object_offset = parent_vma->object_offset;
            vm_object_ref(child_vma->object);
        }

        uintptr_t addr = parent_vma->start;
        while (addr < parent_vma->end) {
            uintptr_t phys = pagemap_translate(parent->map, addr);

            if (phys) {
                uint32_t pte_flags = child_vma->flags;

                if (is_cow || (parent_vma->flags & VMM_FLAG_COW)) {
                    pte_flags &= ~VMM_FLAG_WRITE;
                    pagemap_protect_args_t prot_args = {
                        .virt_addr = (void*)addr,
                        .flags     = pte_flags
                    };

                    pagemap_protect(parent->map, &prot_args);
                }

                pagemap_map_args_t map_args = {
                    .virt_addr = (void*)addr,
                    .phys_addr = (void*)phys,
                    .length    = child_vma->page_size,
                    .flags     = pte_flags,
                    .cache     = child_vma->cache,
                    .page_size = child_vma->page_size,
                };

                if (!pagemap_map(child->map, &map_args)) {
                    KLOG_ERROR("VMM: Failed to map clone page at %p", (void*)addr);
                    kmem_cache_free(vma_cache, child_vma);
                    goto clone_fail;
                }
            }

            addr += parent_vma->page_size;
        }

        vmm_insert_vma(child, child_vma);
        node = rb_next(node);
    }

    release_write(&child->lock);
    release_read(&parent->lock);
    return true;

clone_fail:
    release_write(&child->lock);
    release_read(&parent->lock);
    KLOG_ERROR("VMM: Clone failed. Tearing down partial address space.");
    vmm_destroy_space(child);
    return false;
}