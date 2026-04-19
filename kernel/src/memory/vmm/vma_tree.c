#include "../internal/vma_tree.h"

#include <stdatomic.h>
#include <string.h>

#include "compiler.h"
#include "libs/math.h"
#include "memory/pagemap.h"
#include "memory/vm_object.h"
#include "memory/vma.h"
#include "memory/vmm.h"

#define max(a, b) ((a) > (b) ? (a) : (b))

static inline bool is_kernel_space(struct vm_space* space) {
    return space->map == vmm_get_kernel_pagemap();
}

static inline uintptr_t get_safe_start(struct vm_space* space) {
    return is_kernel_space(space) ? get_kernel_space_start_limit() : USER_SPACE_START;
}

static inline uintptr_t get_safe_end(struct vm_space* space) {
    return is_kernel_space(space) ? KERNEL_SPACE_END : get_user_space_end_limit();
}

static inline bool vma_subtree_can_fit(struct rb_node* node, size_t size) {
    return node && rb_entry(node, struct vm_area, rb_node)->subtree_max_gap >= size;
}

static bool vma_can_merge_prev(
    struct vm_area* prev,
    uintptr_t addr,
    uint32_t flags,
    cache_type_t cache,
    uint8_t page_shift,
    struct vm_object* object,
    size_t object_offset
) {
    if (!prev) return false;

    if (prev->end != addr || prev->flags != flags || prev->cache != cache ||
        prev->page_shift != page_shift || prev->object != object)
        return false;

    return !object || (prev->object_offset + vma_size(prev)) == object_offset;
}

static bool vma_can_merge_next(
    struct vm_area* next,
    uintptr_t addr,
    size_t size,
    uint32_t flags,
    cache_type_t cache,
    uint8_t page_shift,
    struct vm_object* object,
    size_t object_offset
) {
    if (!next) return false;

    if (next->start != addr + size || next->flags != flags || next->cache != cache ||
        next->page_shift != page_shift || next->object != object)
        return false;

    return !object || (object_offset + size) == next->object_offset;
}

bool vma_compute_subtree_gap(struct rb_node* node) {
    struct vm_area* vma = rb_entry(node, struct vm_area, rb_node);
    size_t old_val      = vma->subtree_max_gap;
    size_t max_gap      = vma->own_gap;

    if (node->rb_left) {
        size_t l = rb_entry(node->rb_left, struct vm_area, rb_node)->subtree_max_gap;
        max_gap  = max(max_gap, l);
    }

    if (node->rb_right) {
        size_t r = rb_entry(node->rb_right, struct vm_area, rb_node)->subtree_max_gap;
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

void vmm_insert_vma(struct vm_space* space, struct vm_area* new_vma) {
    if (unlikely(!space || !new_vma)) return;

    struct rb_node** link  = &space->rb_root.rb_node;
    struct rb_node* parent = nullptr;

    while (*link) {
        parent               = *link;
        struct vm_area* curr = rb_entry(parent, struct vm_area, rb_node);

        if (new_vma->start < curr->start)
            link = &parent->rb_left;
        else
            link = &parent->rb_right;
    }

    rb_link_node(&new_vma->rb_node, parent, link);

    struct rb_node* prev = rb_prev(&new_vma->rb_node);
    uintptr_t prev_end =
        prev ? rb_entry(prev, struct vm_area, rb_node)->end : get_safe_start(space);
    new_vma->own_gap = new_vma->start - prev_end;

    struct rb_node* next = rb_next(&new_vma->rb_node);
    if (next) {
        struct vm_area* next_vma = rb_entry(next, struct vm_area, rb_node);
        next_vma->own_gap        = next_vma->start - new_vma->end;
        vma_propagate_gap_up(&next_vma->rb_node);
    }

    rb_insert_augmented(&new_vma->rb_node, &space->rb_root, vma_compute_subtree_gap);
}

struct vm_area* vmm_find_vma_unsafe(struct vm_space* space, uintptr_t addr) {
    struct rb_node* node = space->rb_root.rb_node;

    while (node) {
        struct vm_area* vma = rb_entry(node, struct vm_area, rb_node);

        if (addr < vma->start)
            node = node->rb_left;
        else if (addr >= vma->end)
            node = node->rb_right;
        else
            return vma;
    }

    return nullptr;
}

bool vmm_find_gap_bottom_up(struct vm_space* space, size_t size, size_t align, uintptr_t* addr) {
    if (unlikely(!space || !addr || size == 0)) return false;

    struct rb_node* node = space->rb_root.rb_node;
    uintptr_t safe_start = get_safe_start(space);
    uintptr_t safe_end   = get_safe_end(space);

    struct rb_node* first = rb_first(&space->rb_root);
    uintptr_t first_start = first ? rb_entry(first, struct vm_area, rb_node)->start : safe_end;
    uintptr_t candidate   = align_up(safe_start, align);

    // Check the very bottom of the address space
    if (likely(candidate >= safe_start && candidate + size <= first_start)) {
        *addr = candidate;
        return true;
    }

    while (node) {
        struct vm_area* vma = rb_entry(node, struct vm_area, rb_node);

        if (vma_subtree_can_fit(node->rb_left, size)) {
            node = node->rb_left;
            continue;
        }

        struct rb_node* prev = rb_prev(node);
        uintptr_t prev_end   = prev ? rb_entry(prev, struct vm_area, rb_node)->end : safe_start;
        candidate            = align_up(prev_end, align);

        if (candidate >= prev_end && candidate + size <= vma->start) {
            *addr = candidate;
            return true;
        }

        if (vma_subtree_can_fit(node->rb_right, size)) {
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
        struct vm_area* vma = rb_entry(last, struct vm_area, rb_node);
        candidate           = align_up(vma->end, align);

        if (candidate >= vma->end && candidate + size <= safe_end) {
            *addr = candidate;
            return true;
        }
    }

    return false;
}

bool vmm_find_gap_top_down(struct vm_space* space, size_t size, size_t align, uintptr_t* addr) {
    if (unlikely(!space || !addr || size == 0)) return false;

    uintptr_t safe_start = get_safe_start(space);
    uintptr_t safe_end   = get_safe_end(space);

    if (unlikely(!space->rb_root.rb_node)) {
        if (safe_end >= size && (safe_end - size) >= safe_start) {
            *addr = align_down(safe_end - size, align);
            return (*addr >= safe_start);
        }

        return false;
    }

    struct rb_node* last = rb_last(&space->rb_root);
    if (last) {
        struct vm_area* vma = rb_entry(last, struct vm_area, rb_node);

        if (safe_end >= size) {
            uintptr_t candidate = align_down(safe_end - size, align);
            if (candidate >= vma->end) {
                *addr = candidate;
                return true;
            }
        }
    }

    struct rb_node* node = space->rb_root.rb_node;
    while (node) {
        struct vm_area* vma = rb_entry(node, struct vm_area, rb_node);

        if (vma_subtree_can_fit(node->rb_right, size)) {
            node = node->rb_right;
            continue;
        }

        struct rb_node* prev = rb_prev(node);
        uintptr_t prev_end   = prev ? rb_entry(prev, struct vm_area, rb_node)->end : safe_start;

        if (vma->own_gap >= size && vma->start >= size) {
            uintptr_t candidate = align_down(vma->start - size, align);

            if (candidate >= prev_end) {
                *addr = candidate;
                return true;
            }
        }

        if (vma_subtree_can_fit(node->rb_left, size)) {
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
    struct vm_space* space,
    uintptr_t addr,
    size_t size,
    uint32_t flags,
    cache_type_t cache,
    uint8_t page_shift,
    struct vm_object* object,
    size_t object_offset
) {
    uintptr_t safe_start = get_safe_start(space);
    uintptr_t safe_end   = get_safe_end(space);

    struct vm_area* prev = (addr > safe_start) ? vmm_find_vma_unsafe(space, addr - 1) : nullptr;
    struct vm_area* next =
        ((addr + size) < safe_end) ? vmm_find_vma_unsafe(space, addr + size) : nullptr;

    if (!vma_can_merge_prev(prev, addr, flags, cache, page_shift, object, object_offset))
        prev = nullptr;

    if (!vma_can_merge_next(next, addr, size, flags, cache, page_shift, object, object_offset))
        next = nullptr;

    if (unlikely(!prev && !next)) return false;

    // CASE A: Coalesce (Prev + Current + Next)
    if (prev && next) {
        rb_erase_augmented(&next->rb_node, &space->rb_root, vma_compute_subtree_gap);

        prev->end = next->end;

        struct rb_node* next_next = rb_next(&prev->rb_node);
        if (next_next) {
            struct vm_area* nn_vma = rb_entry(next_next, struct vm_area, rb_node);
            nn_vma->own_gap        = nn_vma->start - prev->end;
            vma_propagate_gap_up(&nn_vma->rb_node);
        }

        vma_propagate_gap_up(&prev->rb_node);

        struct vm_area* cached = atomic_load_explicit(&space->cached_vma, memory_order_relaxed);
        if (cached == next) atomic_store_explicit(&space->cached_vma, prev, memory_order_relaxed);
        if (next->object) vm_object_deref(next->object);

        extern kmem_cache_t* vma_cache;
        kmem_cache_free(vma_cache, next);
        return true;
    }

    // Case B: Merge Left (Prev + Current)
    if (prev) {
        prev->end += size;

        struct rb_node* succ = rb_next(&prev->rb_node);
        if (succ) {
            struct vm_area* succ_vma = rb_entry(succ, struct vm_area, rb_node);
            succ_vma->own_gap        = succ_vma->start - prev->end;
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
        if (next->object) next->object_offset = object_offset;

        vmm_insert_vma(space, next);
        atomic_store_explicit(&space->cached_vma, next, memory_order_relaxed);
        return true;
    }

    return false;
}

struct vm_area* vmm_split_vma(struct vm_space* space, struct vm_area* vma, uintptr_t split_addr) {
    if (unlikely(split_addr <= vma->start || split_addr >= vma->end)) return nullptr;

    extern kmem_cache_t* vma_cache;
    struct vm_area* right_vma = kmem_cache_alloc(vma_cache);
    if (unlikely(!right_vma)) return nullptr;

    memset(right_vma, 0, sizeof(struct vm_area));

    right_vma->start      = split_addr;
    right_vma->end        = vma->end;
    right_vma->flags      = vma->flags;
    right_vma->cache      = vma->cache;
    right_vma->page_shift = vma->page_shift;

    right_vma->object = vma->object;
    if (vma->object) {
        vm_object_ref(vma->object);
        right_vma->object_offset = vma->object_offset + (split_addr - vma->start);
    } else {
        right_vma->object_offset = 0;
    }

    vma->end = split_addr;

    vmm_insert_vma(space, right_vma);
    vma_propagate_gap_up(&vma->rb_node);

    atomic_store_explicit(&space->cached_vma, nullptr, memory_order_relaxed);
    return right_vma;
}