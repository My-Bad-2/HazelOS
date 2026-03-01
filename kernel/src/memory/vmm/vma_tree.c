#include "../internal/vma_tree.h"

#include <stdatomic.h>
#include <string.h>

#include "libs/log.h"
#include "libs/math.h"
#include "memory/pagemap.h"
#include "memory/vm_object.h"
#include "memory/vma.h"

#define max(a, b) ((a) > (b) ? (a) : (b))

bool vma_compute_subtree_gap(struct rb_node* node) {
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

void vma_propagate_gap_up(struct rb_node* node) {
    while (node) {
        vma_compute_subtree_gap(node);
        node = node->rb_parent;
    }
}

void vmm_insert_vma(vm_space_t* space, vm_area_t* new_vma) {
    struct rb_node** link  = &space->rb_root.rb_node;
    struct rb_node* parent = nullptr;

    while (*link) {
        parent          = *link;
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

        vma_propagate_gap_up(&next_vma->rb_node);
    }

    rb_insert_augmented(&new_vma->rb_node, &space->rb_root, vma_compute_subtree_gap);
}

vm_area_t* vmm_find_vma_unsafe(vm_space_t* space, uintptr_t addr) {
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

bool vmm_find_gap_bottom_up(vm_space_t* space, size_t size, size_t align, uintptr_t* addr) {
    struct rb_node* node = space->rb_root.rb_node;
    uintptr_t best_addr  = 0;
    bool found           = false;

    struct rb_node* first = rb_first(&space->rb_root);
    uintptr_t first_start = first ? rb_entry(first, vm_area_t, rb_node)->start : space->end_limit;
    uintptr_t candidate   = align_up(space->start_limit, align);

    if (candidate >= space->start_limit && candidate + size <= first_start) {
        *addr = candidate;
        return true;
    }

    while (node) {
        vm_area_t* vma = rb_entry(node, vm_area_t, rb_node);

        if (node->rb_left && rb_entry(node->rb_left, vm_area_t, rb_node)->subtree_max_gap >= size) {
            node = node->rb_left;
            continue;
        }

        struct rb_node* prev = rb_prev(node);
        uintptr_t prev_end   = prev ? rb_entry(prev, vm_area_t, rb_node)->end : space->start_limit;
        candidate            = align_up(prev_end, align);

        if (candidate >= prev_end && candidate + size <= vma->start) {
            *addr = candidate;
            return true;
        }

        if (node->rb_right &&
            rb_entry(node->rb_right, vm_area_t, rb_node)->subtree_max_gap >= size) {
            node = node->rb_right;
            continue;
        }

        struct rb_node* parent = node->rb_parent;
        while (parent && node == parent->rb_right) {
            node   = parent;
            parent = parent->rb_parent;
        }

        node = parent;
    }

    struct rb_node* last = rb_last(&space->rb_root);
    if (last) {
        vm_area_t* vma = rb_entry(last, vm_area_t, rb_node);
        candidate      = align_up(vma->end, align);

        if (candidate >= vma->end && candidate + size <= space->end_limit) {
            *addr = candidate;
            return true;
        }
    }

    return false;
}

bool vmm_find_gap_top_down(vm_space_t* space, size_t size, size_t align, uintptr_t* addr) {
    if (!space->rb_root.rb_node) {
        if (space->end_limit >= size && (space->end_limit - size) >= space->start_limit) {
            *addr = align_down(space->end_limit - size, align);
            return (*addr >= space->start_limit);
        }

        return false;
    }

    struct rb_node* last = rb_last(&space->rb_root);
    if (last) {
        vm_area_t* vma = rb_entry(last, vm_area_t, rb_node);

        if (space->end_limit >= size) {
            uintptr_t candidate = align_down(space->end_limit - size, align);
            if (candidate >= vma->end) {
                *addr = candidate;
                return true;
            }
        }
    }

    struct rb_node* node = space->rb_root.rb_node;
    while (node) {
        vm_area_t* vma = rb_entry(node, vm_area_t, rb_node);

        if (node->rb_right &&
            rb_entry(node->rb_right, vm_area_t, rb_node)->subtree_max_gap >= size) {
            node = node->rb_right;
            continue;
        }

        struct rb_node* prev = rb_prev(node);
        uintptr_t prev_end   = prev ? rb_entry(prev, vm_area_t, rb_node)->end : space->start_limit;

        if (vma->own_gap >= size && vma->start >= size) {
            uintptr_t candidate = align_down(vma->start - size, align);

            if (candidate >= prev_end) {
                *addr = candidate;
                return true;
            }
        }

        if (node->rb_left && rb_entry(node->rb_left, vm_area_t, rb_node)->subtree_max_gap >= size) {
            node = node->rb_left;
            continue;
        }

        struct rb_node* parent = node->rb_parent;
        while (parent && node == parent->rb_left) {
            node   = parent;
            parent = parent->rb_parent;
        }

        node = parent;
    }

    return false;
}

bool vmm_try_merge(
    vm_space_t* space,
    uintptr_t addr,
    size_t size,
    uint32_t flags,
    cache_type_t cache,
    size_t page_size,
    vm_object_t* object,
    size_t object_offset
) {
    vm_area_t* prev = (addr > space->start_limit) ? vmm_find_vma_unsafe(space, addr - 1) : nullptr;
    vm_area_t* next =
        ((addr + size) < space->end_limit) ? vmm_find_vma_unsafe(space, addr + size) : nullptr;

    if (prev) {
        if (prev->end != addr || prev->flags != flags || prev->cache != cache ||
            prev->page_size != page_size || prev->object != object ||
            (object && (prev->object_offset + prev->size) != object_offset)) {
            prev = nullptr;
        }
    }

    if (next) {
        if (next->start != addr + size || next->flags != flags || next->cache != cache ||
            next->page_size != page_size || next->object != object ||
            (object && (object_offset + size) != next->object_offset)) {
            next = nullptr;
        }
    }

    if (!prev && !next) {
        return false;
    }

    // CASE A: Coalesce (Prev + Current + Next)
    if (prev && next) {
        rb_erase_augmented(&next->rb_node, &space->rb_root, vma_compute_subtree_gap);

        prev->end  = next->end;
        prev->size = prev->end - prev->start;

        struct rb_node* next_next = rb_next(&prev->rb_node);
        if (next_next) {
            vm_area_t* nn_vma = rb_entry(next_next, vm_area_t, rb_node);
            nn_vma->own_gap   = nn_vma->start - prev->end;
            vma_propagate_gap_up(&nn_vma->rb_node);
        }

        vma_propagate_gap_up(&prev->rb_node);

        vm_area_t* cached = atomic_load_explicit(&space->cached_vma, memory_order_relaxed);
        if (cached == next) atomic_store_explicit(&space->cached_vma, prev, memory_order_relaxed);

        if (next->object) {
            vm_object_deref(next->object);
        }

        kmem_cache_free(vma_cache, next);
        return true;
    }

    // Case B: Merge Left (Prev + Current)
    if (prev) {
        prev->end += size;
        prev->size += size;

        struct rb_node* succ = rb_next(&prev->rb_node);
        if (succ) {
            vm_area_t* succ_vma = rb_entry(succ, vm_area_t, rb_node);
            succ_vma->own_gap   = succ_vma->start - prev->end;
            vma_propagate_gap_up(&succ_vma->rb_node);
        }

        vma_propagate_gap_up(&prev->rb_node);
        atomic_store_explicit(&space->cached_vma, prev, memory_order_relaxed);
        return true;
    }

    // Case C: Merge Right (Current + Next)
    if (next) {
        rb_erase_augmented(&next->rb_node, &space->rb_root, vma_compute_subtree_gap);

        next->start = addr;
        next->size += size;

        if (next->object) {
            next->object_offset = object_offset;
        }

        vmm_insert_vma(space, next);
        atomic_store_explicit(&space->cached_vma, next, memory_order_relaxed);
        return true;
    }

    return false;
}

vm_area_t* vmm_split_vma(vm_space_t* space, vm_area_t* vma, uintptr_t split_addr) {
    if (split_addr <= vma->start || split_addr >= vma->end) {
        return nullptr;
    }

    vm_area_t* right_vma = kmem_cache_alloc(vma_cache);
    if (!right_vma) {
        KLOG_ERROR("VMM: OOM during VMA split");
        return nullptr;
    }

    memset(right_vma, 0, sizeof(vm_area_t));

    right_vma->start     = split_addr;
    right_vma->end       = vma->end;
    right_vma->size      = right_vma->end - right_vma->start;
    right_vma->flags     = vma->flags;
    right_vma->cache     = vma->cache;
    right_vma->page_size = vma->page_size;

    right_vma->object = vma->object;
    if (vma->object) {
        vm_object_ref(vma->object);
        right_vma->object_offset = vma->object_offset + (split_addr - vma->start);
    } else {
        right_vma->object_offset = 0;
    }

    vma->end  = split_addr;
    vma->size = vma->end - vma->start;

    vmm_insert_vma(space, right_vma);
    vma_propagate_gap_up(&vma->rb_node);

    atomic_store_explicit(&space->cached_vma, nullptr, memory_order_relaxed);

    return right_vma;
}