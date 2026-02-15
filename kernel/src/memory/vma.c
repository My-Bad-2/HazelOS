#include "memory/vma.h"

#include <llvm-libc-macros/generic-error-number-macros.h>
#include <stdatomic.h>
#include <stdint.h>
#include <string.h>

#include "libs/log.h"
#include "libs/math.h"
#include "libs/rb_tree.h"
#include "libs/spinlock.h"
#include "memory/memory.h"
#include "memory/pagemap.h"
#include "memory/pmm.h"

#define VMA_SLAB_SIZE PAGE_SIZE_SMALL
#define VMAS_PER_SLAB (VMA_SLAB_SIZE / sizeof(vm_area_t))
#define max(a, b)     ((a) > (b) ? (a) : (b))

vm_space_t kernel_space = {0};

static bool vma_compute_subtree_gap(struct rb_node* node) {
    vm_area_t* vma = rb_entry(node, vm_area_t, rb_node);
    size_t old_val = vma->subtree_max_gap;
    size_t max_gap = vma->own_gap;

    if (node->rb_left) {
        size_t l = rb_entry(node->rb_left, vm_area_t, rb_node)->subtree_max_gap;
        max_gap  = max(max_gap, l);
    }

    if (node->rb_right) {
        size_t r = rb_entry(node->rb_right, vm_area_t, rb_node)->subtree_max_gap;
        max_gap  = max(max_gap, r);
    }

    vma->subtree_max_gap = max_gap;
    return old_val != max_gap;
}

static bool find_gap_bottom_up(vm_space_t* space, size_t size, size_t align, uintptr_t* addr);
static void __vmm_insert_vma(vm_space_t* space, vm_area_t* new_vma);

static bool vma_expand_pool(vm_space_t* space) {
    vm_space_t* kspace = &kernel_space;

    bool needs_lock = (space != kspace);

    if (needs_lock) {
        acquire_write(&kspace->lock);
    }

    uintptr_t addr;
    if (!find_gap_bottom_up(kspace, VMA_SLAB_SIZE, PAGE_SIZE_SMALL, &addr)) {
        if (needs_lock) {
            release_write(&kspace->lock);
        }

        return false;
    }

    void* phys = pmm_alloc(1);
    if (!phys) {
        if (needs_lock) {
            release_write(&kspace->lock);
        }

        return false;
    }

    pagemap_map_args_t args = {
        .virt_addr = (void*)addr,
        .phys_addr = phys,
        .length    = VMA_SLAB_SIZE,
        .flags     = VMM_FLAG_READ | VMM_FLAG_WRITE,
        .cache     = CACHE_WRITE_BACK,
        .page_size = PAGE_SIZE_SMALL,
    };

    if (!pagemap_map(kspace->map, &args)) {
        PANIC("VMM: Failed to map vma pool!");
    }

    vm_area_t* new_slab = (vm_area_t*)addr;
    memset(new_slab, 0, VMA_SLAB_SIZE);

    vm_area_t* meta_vma = &new_slab[0];
    meta_vma->start     = addr;
    meta_vma->end       = addr + VMA_SLAB_SIZE;
    meta_vma->size      = VMA_SLAB_SIZE;
    meta_vma->page_size = PAGE_SIZE_SMALL;
    meta_vma->flags     = VMM_FLAG_READ | VMM_FLAG_WRITE;
    meta_vma->cache     = CACHE_WRITE_BACK;

    __vmm_insert_vma(kspace, meta_vma);

    for (int i = 1; i < VMAS_PER_SLAB - 1; ++i) {
        vm_area_t** vma = (vm_area_t**)&new_slab[i];
        *vma            = &new_slab[i + 1];
    }

    *(vm_area_t**)(&new_slab[VMAS_PER_SLAB - 1]) = space->free_vma_pool;
    space->free_vma_pool                         = &new_slab[1];

    if (needs_lock) {
        release_write(&kspace->lock);
    }

    return true;
}

static vm_area_t* vma_new(vm_space_t* space) {
    if (!space->free_vma_pool) {
        if (!vma_expand_pool(space)) {
            return nullptr;
        }
    }

    vm_area_t* vma       = space->free_vma_pool;
    space->free_vma_pool = *(vm_area_t**)vma;
    memset(vma, 0, sizeof(vm_area_t));

    return vma;
}

static void vma_free_struct(vm_space_t* space, vm_area_t* vma) {
    *(vm_area_t**)vma    = space->free_vma_pool;
    space->free_vma_pool = vma;
}

static bool find_gap_bottom_up(vm_space_t* space, size_t size, size_t align, uintptr_t* addr) {
    struct rb_node* node = space->rb_root.rb_node;

    if (!node) {
        uintptr_t candidate = align_up(space->start_limit, align);

        if (candidate + size <= space->end_limit) {
            *addr = candidate;
            return true;
        }

        return false;
    }

    while (node) {
        if (node->rb_left && rb_entry(node->rb_left, vm_area_t, rb_node)->subtree_max_gap >= size) {
            node = node->rb_left;
            continue;
        }

        while (true) {
            vm_area_t* vma = rb_entry(node, vm_area_t, rb_node);

            struct rb_node* prev = rb_prev(node);
            uintptr_t prev_end =
                prev ? rb_entry(prev, vm_area_t, rb_node)->end : space->start_limit;

            uintptr_t candidate = align_up(prev_end, align);

            if (candidate + size <= vma->start) {
                *addr = candidate;
                return true;
            }

            if (node->rb_right &&
                rb_entry(node->rb_right, vm_area_t, rb_node)->subtree_max_gap >= size) {
                node = node->rb_right;
                break;
            }

            struct rb_node* parent = node->rb_parent;

            if (!parent) {
                goto check_tail;
            }

            while (parent && node == parent->rb_right) {
                node   = parent;
                parent = parent->rb_parent;
            }

            if (!parent) {
                goto check_tail;
            }

            node = parent;
        }
    }

check_tail:
    // Try tail
    struct rb_node* last = rb_last(&space->rb_root);
    if (last) {
        vm_area_t* vma      = rb_entry(last, vm_area_t, rb_node);
        uintptr_t candidate = align_up(vma->end, align);

        if (candidate + size <= space->end_limit) {
            *addr = candidate;
            return true;
        }
    }

    return false;
}

static vm_area_t* __vmm_find_vma_unsafe(vm_space_t* space, uintptr_t addr) {
    struct rb_node* node = space->rb_root.rb_node;

    while (node) {
        vm_area_t* vma = rb_entry(node, vm_area_t, rb_node);

        if (addr < vma->start) {
            node = node->rb_left;
        } else if (addr >= vma->end) {
            node = node->rb_right;
        } else {
            return vma;
        }
    }

    return nullptr;
}

static vm_area_t* vmm_find_vma(vm_space_t* space, uintptr_t addr) {
    acquire_read(&space->lock);

    vm_area_t* cached = atomic_load_explicit(&space->cached_vma, memory_order_acquire);
    if (cached && addr >= cached->start && addr < cached->end) {
        release_read(&space->lock);
        return cached;
    }

    vm_area_t* vma = __vmm_find_vma_unsafe(space, addr);

    if (vma) {
        atomic_store_explicit(&space->cached_vma, vma, memory_order_relaxed);
    }

    release_read(&space->lock);
    return vma;
}

static bool vmm_try_merge(
    vm_space_t* space,
    uintptr_t addr,
    size_t size,
    uint32_t flags,
    cache_type_t cache,
    size_t page_size
) {
    vm_area_t* prev =
        (addr > space->start_limit) ? __vmm_find_vma_unsafe(space, addr - 1) : nullptr;
    vm_area_t* next =
        ((addr + size) < space->end_limit) ? __vmm_find_vma_unsafe(space, addr + size) : nullptr;

    if (prev) {
        if ((prev->end != addr || prev->flags != flags || prev->cache != cache ||
             prev->page_size != page_size)) {
            prev = nullptr;
        }
    }

    if (next) {
        if ((next->end != addr || next->flags != flags || next->cache != cache ||
             next->page_size != page_size)) {
            next = nullptr;
        }
    }

    bool merged = false;

    // Case A: Merge Left
    if (prev) {
        rb_erase_augmented(&prev->rb_node, &space->rb_root, vma_compute_subtree_gap);

        prev->end += size;
        prev->size += size;

        // Case B: Coalesce (Prev + New + Next)
        if (next) {
            rb_erase_augmented(&next->rb_node, &space->rb_root, vma_compute_subtree_gap);

            prev->end = next->end;
            prev->size += next->size;

            vm_area_t* cached = atomic_load_explicit(&space->cached_vma, memory_order_relaxed);
            if (cached == next) {
                atomic_store_explicit(&space->cached_vma, prev, memory_order_relaxed);
            }

            vma_free_struct(space, next);
        }

        __vmm_insert_vma(space, prev);

        atomic_store_explicit(&space->cached_vma, prev, memory_order_relaxed);
        return true;
    }

    // Case C: Merge Right
    if (next) {
        rb_erase_augmented(&next->rb_node, &space->rb_root, vma_compute_subtree_gap);

        next->start = addr;
        next->size += size;

        __vmm_insert_vma(space, next);

        atomic_store_explicit(&space->cached_vma, next, memory_order_relaxed);
        return true;
    }

    return false;
}

static void __vmm_insert_vma(vm_space_t* space, vm_area_t* new_vma) {
    struct rb_node** link  = &space->rb_root.rb_node;
    struct rb_node* parent = nullptr;

    while (*link) {
        parent = *link;

        vm_area_t* curr = rb_entry(parent, vm_area_t, rb_node);

        if (new_vma->start < curr->start) {
            link = &parent->rb_left;
        } else {
            link = &parent->rb_right;
        }
    }

    rb_link_node(&new_vma->rb_node, parent, link);

    struct rb_node* prev = rb_prev(&new_vma->rb_node);
    uintptr_t prev_end   = prev ? rb_entry(prev, vm_area_t, rb_node)->end : space->start_limit;
    new_vma->own_gap     = new_vma->start - prev_end;

    struct rb_node* next = rb_next(&new_vma->rb_node);
    if (next) {
        vm_area_t* next_vma = rb_entry(next, vm_area_t, rb_node);
        next_vma->own_gap   = next_vma->start - new_vma->end;
    }

    rb_insert_augmented(&new_vma->rb_node, &space->rb_root, vma_compute_subtree_gap);
}

static size_t select_page_size(size_t size) {
    if (size >= PAGE_SIZE_LARGE && (size % PAGE_SIZE_LARGE == 0)) {
        return PAGE_SIZE_LARGE;
    }

    if (size >= PAGE_SIZE_MEDIUM && (size % PAGE_SIZE_MEDIUM == 0)) {
        return PAGE_SIZE_MEDIUM;
    }

    return PAGE_SIZE_SMALL;
}

static size_t select_page_size_addr(size_t size, uintptr_t addr) {
    if (size >= PAGE_SIZE_LARGE && (size % PAGE_SIZE_LARGE == 0) && (addr % PAGE_SIZE_LARGE == 0)) {
        return PAGE_SIZE_LARGE;
    }

    if (size >= PAGE_SIZE_MEDIUM && (size % PAGE_SIZE_MEDIUM == 0) &&
        (addr % PAGE_SIZE_MEDIUM == 0)) {
        return PAGE_SIZE_MEDIUM;
    }

    return PAGE_SIZE_SMALL;
}

static bool find_gap_top_down_recurse(
    struct rb_node* node,
    size_t size,
    size_t align,
    uintptr_t start_limit,
    uintptr_t* found_addr
) {
    if (!node) {
        return false;
    }

    vm_area_t* vma = rb_entry(node, vm_area_t, rb_node);

    // Try Right Subtree (Highest addresses)
    if (node->rb_right) {
        vm_area_t* right = rb_entry(node->rb_right, vm_area_t, rb_node);
        if (right->subtree_max_gap >= size) {
            if (find_gap_top_down_recurse(node->rb_right, size, align, start_limit, found_addr)) {
                return true;
            }
        }
    }

    // Try Own Gap
    struct rb_node* prev = rb_prev(node);
    uintptr_t prev_end   = prev ? rb_entry(prev, vm_area_t, rb_node)->end : start_limit;

    if (vma->own_gap >= size) {
        if (vma->start >= size) {
            uintptr_t candidate = align_down(vma->start - size, align);
            if (candidate >= prev_end) {
                *found_addr = candidate;
                return true;
            }
        }
    }

    // Try Left Subtree
    if (node->rb_left) {
        vm_area_t* left = rb_entry(node->rb_left, vm_area_t, rb_node);
        if (left->subtree_max_gap >= size) {
            if (find_gap_top_down_recurse(node->rb_left, size, align, start_limit, found_addr)) {
                return true;
            }
        }
    }

    return false;
}

static bool find_gap_top_down(vm_space_t* space, size_t size, size_t align, uintptr_t* addr) {
    if (!space->rb_root.rb_node) {
        if (space->end_limit >= size && (space->end_limit - size) >= space->start_limit) {
            *addr = align_down(space->end_limit - size, align);
            return (*addr >= space->start_limit);
        }
        return false;
    }

    // Check tail gap (space b/w last node and end_limit)
    struct rb_node* last = rb_last(&space->rb_root);
    if (last) {
        vm_area_t* vma = rb_entry(last, vm_area_t, rb_node);

        if (space->end_limit >= size) {
            uintptr_t top_candidate = align_down(space->end_limit - size, align);

            if (top_candidate >= vma->end) {
                *addr = top_candidate;
                return true;
            }
        }
    }

    // Tree Descent (Right -> Self -> Left)
    return find_gap_top_down_recurse(space->rb_root.rb_node, size, align, space->start_limit, addr);
}

static void vmm_unmap_and_free(vm_space_t* space, uintptr_t start, size_t size, size_t page_size) {
    uintptr_t addr = start;
    uintptr_t end  = start + size;

    while (addr < end) {
        // 1. Get Physical Address
        uintptr_t phys = pagemap_translate(space->map, addr);

        if (phys) {
            pagemap_unmap_args_t args = {
                .virt_addr = (void*)addr,
                .length    = page_size,
                .free_phys = true,
            };

            pagemap_unmap(space->map, &args);
        }

        addr += page_size;
    }
}

static bool vmm_map_range(
    vm_space_t* space,
    uintptr_t start,
    size_t size,
    size_t page_size,
    uint32_t flags,
    cache_type_t cache
) {
    if (flags == VMM_FLAG_GUARD) {
        return true;
    }

    uintptr_t addr       = start;
    uintptr_t end        = start + size;
    size_t frames_needed = page_size / PAGE_SIZE_SMALL;

    while (addr < end) {
        void* phys = pmm_alloc(frames_needed);

        if (!phys) {
            if (addr > start) {
                vmm_unmap_and_free(space, start, addr - start, page_size);
            }

            return false;
        }

        pagemap_map_args_t args = {
            .virt_addr = (void*)addr,
            .phys_addr = phys,
            .length    = page_size,
            .flags     = flags,
            .cache     = cache,
            .page_size = page_size,
        };

        if (!pagemap_map(space->map, &args)) {
            if (addr > start) {
                vmm_unmap_and_free(space, start, addr - start, page_size);
            }

            return false;
        }

        addr += page_size;
    }

    return true;
}

void* vmalloc(
    vm_space_t* space,
    size_t size,
    uint32_t flags,
    cache_type_t cache,
    size_t alignment
) {
    if (size == 0) {
        return nullptr;
    }

    if (alignment < PAGE_SIZE_SMALL) {
        alignment = PAGE_SIZE_SMALL;
    }

    size = align_up(size, PAGE_SIZE_SMALL);

    bool is_stack      = (flags & VMM_FLAG_STACK);
    size_t actual_size = size + (is_stack ? PAGE_SIZE_SMALL : 0);

    size_t ps    = select_page_size(size);
    size_t align = (ps > alignment) ? ps : alignment;

    acquire_write(&space->lock);

    uintptr_t addr  = 0;
    size_t final_ps = PAGE_SIZE_SMALL;
    bool found      = false;

    if (is_stack) {
        if (ps > PAGE_SIZE_SMALL) {
            found = find_gap_top_down(space, actual_size, align, &addr);

            if (found) {
                final_ps = ps;
            }
        }

        if (!found && (ps == PAGE_SIZE_SMALL || alignment < align)) {
            found    = find_gap_top_down(space, actual_size, alignment, &addr);
            final_ps = PAGE_SIZE_SMALL;
        }
    } else {
        if (ps > PAGE_SIZE_SMALL) {
            found = find_gap_bottom_up(space, actual_size, align, &addr);

            if (found) {
                final_ps = ps;
            }
        }

        if (!found && (ps == PAGE_SIZE_SMALL || alignment < align)) {
            found    = find_gap_bottom_up(space, actual_size, alignment, &addr);
            final_ps = PAGE_SIZE_SMALL;
        }
    }

    if (!found) {
        KLOG_WARN("VMM: Failed to allocate VMA of size %zu", size);
        release_write(&space->lock);
        return nullptr;
    }

    if (is_stack) {
        uintptr_t stack_start = addr + PAGE_SIZE_SMALL;

        if (!vmm_map_range(space, stack_start, size, final_ps, flags & ~VMM_FLAG_STACK, cache)) {
            KLOG_ERROR("VMM: Failed to map stack range at %p", (void*)stack_start);
            release_write(&space->lock);
            return nullptr;
        }
    } else {
        if (!vmm_map_range(space, addr, size, final_ps, flags, cache)) {
            KLOG_ERROR("VMM: Failed to map range at %p", (void*)addr);
            release_write(&space->lock);
            return nullptr;
        }
    }

    // if (!is_stack) {
    //     if (vmm_try_merge(space, addr, size, flags, cache, final_ps)) {
    //         release_write(&space->lock);
    //         return (void*)addr;
    //     }
    // }

    if (is_stack) {
        vm_area_t* guard = vma_new(space);
        vm_area_t* stack = vma_new(space);

        if (!guard || !stack) {
            vmm_unmap_and_free(space, addr + PAGE_SIZE_SMALL, size, final_ps);

            if (guard) {
                vma_free_struct(space, guard);
            }

            if (stack) {
                vma_free_struct(space, stack);
            }

            release_write(&space->lock);
            return nullptr;
        }

        guard->start     = addr;
        guard->end       = addr + PAGE_SIZE_SMALL;
        guard->size      = PAGE_SIZE_SMALL;
        guard->page_size = PAGE_SIZE_SMALL;
        guard->flags     = VMM_FLAG_GUARD;
        guard->cache     = CACHE_WRITE_BACK;
        __vmm_insert_vma(space, guard);

        stack->start     = addr + PAGE_SIZE_SMALL;
        stack->end       = addr + actual_size;
        stack->size      = actual_size;
        stack->page_size = final_ps;
        stack->flags     = flags & ~VMM_FLAG_STACK;
        stack->cache     = cache;
        __vmm_insert_vma(space, stack);

        atomic_store_explicit(&space->cached_vma, stack, memory_order_relaxed);
        release_write(&space->lock);
        return (void*)stack->start;
    } else {
        vm_area_t* vma = vma_new(space);

        if (!vma) {
            vmm_unmap_and_free(space, addr, size, final_ps);
            release_write(&space->lock);
            return nullptr;
        }

        vma->start     = addr;
        vma->end       = addr + actual_size;
        vma->size      = actual_size;
        vma->page_size = final_ps;
        vma->flags     = flags;
        vma->cache     = cache;

        __vmm_insert_vma(space, vma);
        space->allocation_hint = vma->end;

        atomic_store_explicit(&space->cached_vma, vma, memory_order_relaxed);
        release_write(&space->lock);
        return (void*)addr;
    }
}

void* vmalloc_addr(
    vm_space_t* space,
    void* ptr,
    size_t size,
    uint32_t flags,
    cache_type_t cache,
    size_t alignment
) {
    uintptr_t addr = (uintptr_t)ptr;

    if (size == 0) {
        return nullptr;
    }

    if (alignment < PAGE_SIZE_SMALL) {
        alignment = PAGE_SIZE_SMALL;
    }

    if (!is_aligned(addr, alignment)) {
        return nullptr;
    }

    size = align_up(size, PAGE_SIZE_SMALL);

    if (addr < space->start_limit || size > space->end_limit || addr > space->end_limit - size) {
        return nullptr;
    }

    size_t final_ps = select_page_size_addr(size, addr);
    size_t align    = (final_ps > alignment) ? final_ps : alignment;

    acquire_write(&space->lock);

    struct rb_node* node = space->rb_root.rb_node;
    bool collision       = false;

    while (node) {
        vm_area_t* curr = rb_entry(node, vm_area_t, rb_node);

        if (addr < curr->end && curr->start < (addr + size)) {
            collision = true;
            break;
        }

        if (addr < curr->start) {
            node = node->rb_left;
        } else {
            node = node->rb_right;
        }
    }

    if (collision) {
        KLOG_WARN("VMM: Fixed allocation collision at %p (size: %zu)", ptr, size);
        release_write(&space->lock);
        return nullptr;
    }

    if (!vmm_map_range(space, addr, size, final_ps, flags, cache)) {
        KLOG_ERROR("VMM: Failed to map fixed range at %p", ptr);
        release_write(&space->lock);
        return nullptr;
    }

    // if (vmm_try_merge(space, addr, size, flags, cache, final_ps)) {
    //     release_write(&space->lock);
    //     return ptr;
    // }

    vm_area_t* vma = vma_new(space);

    if (!vma) {
        vmm_unmap_and_free(space, addr, size, final_ps);
        release_write(&space->lock);
        return nullptr;
    }

    vma->start     = addr;
    vma->end       = addr + size;
    vma->size      = size;
    vma->page_size = final_ps;
    vma->flags     = flags;
    vma->cache     = cache;

    __vmm_insert_vma(space, vma);
    atomic_store_explicit(&space->cached_vma, vma, memory_order_relaxed);

    release_write(&space->lock);
    return ptr;
}

// void vmm_free(vm_space_t* space, void* ptr, size_t size) {
//     uintptr_t start = (uintptr_t)ptr;
//     uintptr_t end   = start + size;

//     if (size == 0) {
//         return;
//     }

//     acquire_write(&space->lock);

//     while (start < end) {
//         vm_area_t* vma = __vmm_find_vma_unsafe(space, start);

//         if (!vma) {
//             struct rb_node* node = space->rb_root.rb_node;
//             vm_area_t* next      = nullptr;

//             while (node) {
//                 vm_area_t* curr = rb_entry(node, vm_area_t, rb_node);

//                 if (curr->start > start) {
//                     next = curr;
//                     node = node->rb_left;
//                 } else {
//                     node = node->rb_right;
//                 }
//             }

//             if (!next || next->start >= end) {
//                 break;
//             }

//             start = next->start;
//             vma   = next;
//         }

//         uintptr_t free_start = max(start, vma->start);
//         uintptr_t free_end   = (end < vma->end) ? end : vma->end;
//         size_t free_size     = free_end - free_start;

//         if (free_size == 0) {
//             start = vma->end;
//             continue;
//         }

//         vmm_unmap_and_free(space, free_start, free_size, vma->page_size);

//         // Case A: Full Removal
//         if (free_start == vma->start && free_end == vma->end) {
//             // If this is a stack, check if there is a guard below it
//             if (vma->flags & VMM_FLAG_STACK) {
//                 struct rb_node* prev = rb_prev(&vma->rb_node);

//                 if (prev) {
//                     vm_area_t* guard = rb_entry(prev, vm_area_t, rb_node);

//                     if ((guard->flags == VMM_FLAG_GUARD) && (guard->end == vma->start)) {
//                         rb_erase_augmented(
//                             &guard->rb_node,
//                             &space->rb_root,
//                             vma_compute_subtree_gap
//                         );
//                         vma_free_struct(space, guard);
//                     }
//                 }
//             }

//             rb_erase_augmented(&vma->rb_node, &space->rb_root, vma_compute_subtree_gap);

//             vm_area_t* expected = vma;
//             atomic_compare_exchange_strong(&space->cached_vma, &expected, nullptr);

//             vma_free_struct(space, vma);
//         } else if (free_start == vma->start) {
//             // Case B: Head Cut (Shrink from the left)
//             rb_erase_augmented(&vma->rb_node, &space->rb_root, vma_compute_subtree_gap);

//             vma->start = free_end;
//             vma->size  = vma->end - vma->start;

//             __vmm_insert_vma(space, vma);
//         } else if (free_end == vma->end) {
//             // Case C: Tail Cut (Shrink from the right)
//             rb_erase_augmented(&vma->rb_node, &space->rb_root, vma_compute_subtree_gap);

//             vma->start = free_start;
//             vma->size  = vma->end - vma->start;

//             __vmm_insert_vma(space, vma);
//         } else {
//             // Case D: Splitting (Hole punched in the middle)
//             vm_area_t* right = vma_new(space);

//             if (!right) {
//                 PANIC("VMM: OOM during VMA split");
//             }

//             rb_erase_augmented(&vma->rb_node, &space->rb_root, vma_compute_subtree_gap);

//             right->start     = free_end;
//             right->end       = vma->end;
//             right->size      = right->end - right->start;
//             right->flags     = vma->flags;
//             right->cache     = vma->cache;
//             right->page_size = vma->page_size;

//             vma->end  = free_start;
//             vma->size = vma->end - vma->start;

//             __vmm_insert_vma(space, vma);
//             __vmm_insert_vma(space, right);
//         }

//         start = free_end;
//     }

//     atomic_store)explicit(&space->cached_vma, nullptr, memory_order_relaxed);
//     release_write(&space->lock);
// }

void vmfree(vm_space_t* space, void* ptr, size_t) {
    uintptr_t addr = (uintptr_t)ptr;
    acquire_write(&space->lock);

    struct rb_node* node = space->rb_root.rb_node;
    vm_area_t* vma       = nullptr;

    while (node) {
        vm_area_t* curr = rb_entry(node, vm_area_t, rb_node);

        if (addr < curr->start) {
            node = node->rb_left;
        } else if (addr >= curr->end) {
            node = node->rb_right;
        } else {
            vma = curr;
            break;
        }
    }

    if (!vma || vma->start != addr) {
        release_write(&space->lock);
        return;
    }

    vm_area_t* to_free[2];
    int count  = 1;
    to_free[0] = vma;

    if (vma->flags & VMM_FLAG_STACK) {
        struct rb_node* prev = rb_prev(&vma->rb_node);

        if (prev) {
            vm_area_t* prev_vma = rb_entry(prev, vm_area_t, rb_node);

            if ((prev_vma->flags & VMM_FLAG_GUARD) && (prev_vma->end == vma->start)) {
                to_free[1] = prev_vma;
                count      = 2;
            }
        }
    }

    for (int i = 0; i < count; i++) {
        vm_area_t* target = to_free[i];

        vmm_unmap_and_free(space, target->start, target->size, target->page_size);
        rb_erase_augmented(&target->rb_node, &space->rb_root, vma_compute_subtree_gap);

        node                 = space->rb_root.rb_node;
        vm_area_t* next_vma  = NULL;
        struct rb_node* curr = space->rb_root.rb_node;

        while (curr) {
            vm_area_t* c = rb_entry(curr, vm_area_t, rb_node);

            if (c->start > target->start) {
                next_vma = c;
                curr     = curr->rb_left;
            } else {
                curr = curr->rb_right;
            }
        }

        if (next_vma) {
            struct rb_node* prev = rb_prev(&next_vma->rb_node);
            uintptr_t prev_end =
                prev ? rb_entry(prev, vm_area_t, rb_node)->end : space->start_limit;
            next_vma->own_gap = next_vma->start - prev_end;

            struct rb_node* up = &next_vma->rb_node;
            while (up) {
                vma_compute_subtree_gap(up);
                up = up->rb_parent;
            }
        }

        vm_area_t* expected = target;
        atomic_compare_exchange_strong(&space->cached_vma, &expected, nullptr);

        vma_free_struct(space, target);
    }

    release_write(&space->lock);
}

void vmm_init_global(void) {}

void vmm_init_space(vm_space_t* space, pagemap_t* map, uintptr_t start, uintptr_t end) {
    memset(space, 0, sizeof(vm_space_t));

    space->rb_root         = RB_ROOT;
    space->map             = map;
    space->start_limit     = start;
    space->end_limit       = end;
    space->allocation_hint = start;

    atomic_init(&space->cached_vma, nullptr);
    create_rwlock(&space->lock);

    vma_expand_pool(space);
}

static uint32_t sys_flags_to_vmm(int prot, int flags) {
    uint32_t ret = VMM_FLAG_USER;

    if (prot & PROT_EXEC) {
        ret |= VMM_FLAG_EXECUTE;
    }

    if (prot & PROT_READ) {
        ret |= VMM_FLAG_READ;
    }

    if (prot & PROT_WRITE) {
        ret |= VMM_FLAG_WRITE;
    }

    if (flags & MAP_GROWSDOWN || flags & MAP_STACK) {
        ret |= VMM_FLAG_STACK;
    }

    if (flags & MAP_SHARED) {
        ret |= VMM_FLAG_SHARED;
    }

    return ret;
}

static size_t get_page_size_from_flags(int flags) {
    if (!(flags & MAP_HUGETLB)) {
        return PAGE_SIZE_SMALL;
    }

    uint32_t huge_page_code = (flags >> MAP_HUGE_SHIFT) & MAP_HUGE_MASK;

    if (huge_page_code == 0) {
        return PAGE_SIZE_MEDIUM;
    }

    return 1ul << huge_page_code;
}

void* sys_mmap(
    vm_space_t* space,
    void* addr,
    size_t length,
    int prot,
    int flags,
    int fd,
    long offset
) {
    if (!length || !space) {
        return (void*)-EINVAL;
    }

    size_t page_size = get_page_size_from_flags(flags);

    if (page_size != PAGE_SIZE_SMALL && page_size != PAGE_SIZE_MEDIUM &&
        page_size != PAGE_SIZE_LARGE) {
        return (void*)-EINVAL;
    }

    size_t aligned_length = align_up(length, page_size);
    cache_type_t cache    = CACHE_WRITE_BACK;
    uint32_t vma_flags    = sys_flags_to_vmm(prot, flags);

    if (flags & MAP_FIXED || addr) {
        return vmalloc_addr(space, addr, aligned_length, vma_flags, cache, page_size);
    }

    return vmalloc(space, aligned_length, vma_flags, cache, page_size);
}

int sys_munmmap(vm_space_t* space, void* addr, size_t length) {
    if (!space || !addr) {
        return -EINVAL;
    }

    vmfree(space, addr, length);
    return 0;
}

int sys_mprotect(vm_space_t* space, void* addr, size_t size, int prot) {
    if (!space || !addr) {
        return -EINVAL;
    }

    uint32_t flags = sys_flags_to_vmm(prot, 0);

    pagemap_protect_args_t args = {
        .virt_addr = (uint8_t*)addr + size,
        .flags     = flags,
    };

    pagemap_protect(space->map, &args);
    return 0;
}