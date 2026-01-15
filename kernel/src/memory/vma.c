#include "memory/vma.h"

#include <errno.h>
#include <stdint.h>
#include <string.h>

#include "arch.h"
#include "boot/boot.h"
#include "compiler.h"
#include "libs/log.h"
#include "libs/math.h"
#include "libs/spinlock.h"
#include "memory/memory.h"
#include "memory/pagemap.h"
#include "memory/pmm.h"

#define RB_BLACK 0
#define RB_RED   1

#define VMA_CACHE_SIZE 64
#define VMA_BATCH_SIZE 32

vm_space_t kernel_space;
uintptr_t shared_zero_page = 0;

typedef struct vma_slab_page {
    struct vma_slab_page* next;
} vma_slab_page_t;

typedef struct {
    vm_area_t* objects[VMA_CACHE_SIZE];
    int count;
} vma_cpu_cache_t;

static vma_cpu_cache_t* vma_cache;
static size_t cpu_count;
static irq_lock_t irq_lock;

static struct {
    vm_area_t* free_list;
    vma_slab_page_t* pages;
    interrupt_lock_t lock;
} vma_slab;

void vmm_init_global(void) {
    vma_slab.free_list = nullptr;
    vma_slab.pages     = nullptr;
    create_interrupt_lock(&vma_slab.lock);

    cpu_count        = mp_request.response->cpu_count;
    size_t num_pages = div_roundup(cpu_count * sizeof(vma_cpu_cache_t), PAGE_SIZE_SMALL);

    void* ptr = pmm_alloc(num_pages);

    if (!ptr) {
        errno = ENOMEM;
        KLOG_ERROR("VMM: failed to allocate cpu cache\n");
        return;
    }

    vma_cache = (vma_cpu_cache_t*)to_higher_half((uintptr_t)ptr);

    for (size_t i = 0; i < cpu_count; ++i) {
        vma_cache[i].count = 0;

        memset((void*)vma_cache->objects, 0, VMA_CACHE_SIZE * sizeof(vm_area_t*));
    }

    ptr = pmm_alloc(1);

    if (!ptr) {
        errno = ENOMEM;
        KLOG_ERROR("VMM: failed to allocate shared zero page\n");
        return;
    }

    memset((void*)to_higher_half((uintptr_t)ptr), 0, PAGE_SIZE_SMALL);

    shared_zero_page = (uintptr_t)ptr;
}

static int global_slab_alloc_bulk(vm_area_t** out, int count) {
    ASSERT(out);

    acquire_interrupt_lock(&vma_slab.lock);

    int gathered = 0;

    while (gathered < count) {
        if (likely(vma_slab.free_list)) {
            out[gathered++]    = vma_slab.free_list;
            vma_slab.free_list = vma_slab.free_list->next_free;
            continue;
        }

        void* p = pmm_alloc(1);

        if (!p) {
            errno = ENOMEM;
            KLOG_ERROR("VMM: failed to allocate VMA slab page\n");
            break;
        }

        uintptr_t page = to_higher_half((uintptr_t)p);

        // Setup Page header
        vma_slab_page_t* header = (vma_slab_page_t*)page;
        header->next            = vma_slab.pages;
        vma_slab.pages          = header;

        // Slice the page into objects
        uintptr_t start = (uintptr_t)page + sizeof(vma_slab_page_t);
        uintptr_t end   = (uintptr_t)page + PAGE_SIZE_SMALL;

        if (!is_aligned(start, _Alignof(vm_area_t))) {
            start = align_down(start, _Alignof(vm_area_t));
        }

        vm_area_t* curr = (vm_area_t*)start;
        vm_area_t* prev = nullptr;

        // Link them all together
        while ((uintptr_t)curr + sizeof(vm_area_t) <= end) {
            if (prev) {
                prev->next_free = curr;
            }

            prev = curr;
            curr = (vm_area_t*)((uintptr_t)curr + sizeof(vm_area_t));
        }

        if (prev) {
            // Attach this new chain to the global free list
            prev->next_free    = vma_slab.free_list;
            vma_slab.free_list = (vm_area_t*)start;
        }
    }

    release_interrupt_lock(&vma_slab.lock);
    return gathered;
}

static void global_slab_free_bulk(vm_area_t** ptrs, int count) {
    acquire_interrupt_lock(&vma_slab.lock);

    for (int i = 0; i < count; ++i) {
        ptrs[i]->next_free = vma_slab.free_list;
        vma_slab.free_list = ptrs[i];
    }

    release_interrupt_lock(&vma_slab.lock);
}

static vm_area_t* alloc_vm_area_struct() {
    acquire_irq_lock(&irq_lock);

    uint32_t cpu           = arch_get_core_idx();
    vma_cpu_cache_t* cache = &vma_cache[cpu];
    vm_area_t* obj         = nullptr;

    if (likely(cache->count > 0)) {
        cache->count--;
        obj = cache->objects[cache->count];
        release_irq_lock(&irq_lock);
        return obj;
    }

    release_irq_lock(&irq_lock);

    vm_area_t* batch[VMA_BATCH_SIZE];

    int fetched = global_slab_alloc_bulk(batch, VMA_BATCH_SIZE);

    if (fetched == 0) {
        return nullptr;
    }

    acquire_irq_lock(&irq_lock);

    // Refresh CPU ID
    cpu   = arch_get_core_idx();
    cache = &vma_cache[cpu];

    // Something for the user
    obj = batch[0];

    int items_to_cache = fetched - 1;
    int start_idx      = 1;

    int available_slots = VMA_CACHE_SIZE - cache->count;
    int fill_count      = (items_to_cache > available_slots) ? available_slots : items_to_cache;

    // Fill all the available slots
    for (int i = 1; i < fill_count; ++i) {
        cache->objects[cache->count++] = batch[start_idx + i];
    }

    int leftovers = items_to_cache - fill_count;

    if (unlikely(leftovers > 0)) {
        // Since we own these pointers but have nowhere to put them locally. We must return them to
        // the global slab immediately.
        vm_area_t** leftover_ptrs = &batch[start_idx + fill_count];
        release_irq_lock(&irq_lock);

        // Return excess back to the global pool
        global_slab_free_bulk(leftover_ptrs, leftovers);
    } else {
        release_irq_lock(&irq_lock);
    }

    return obj;
}

static void free_vm_area_struct(vm_area_t* ptr) {
    if (!ptr) {
        return;
    }

    acquire_irq_lock(&irq_lock);

    uint32_t cpu           = arch_get_core_idx();
    vma_cpu_cache_t* cache = &vma_cache[cpu];
    vm_area_t* obj         = nullptr;

    // Check if Cache is full
    if (likely(cache->count < VMA_CACHE_SIZE)) {
        cache->objects[cache->count++] = ptr;
        release_irq_lock(&irq_lock);
        return;
    }

    // Cache is full
    vm_area_t* batch_to_flush[VMA_BATCH_SIZE];

    // Return flushed items to Global Slab
    for (int i = 0; i < VMA_BATCH_SIZE; ++i) {
        cache->count--;
        batch_to_flush[i] = cache->objects[cache->count];
    }

    cache->objects[cache->count++] = ptr;

    release_irq_lock(&irq_lock);
    global_slab_free_bulk(batch_to_flush, VMA_BATCH_SIZE);
}

static void vmm_recalculate_max_gap(vm_area_t* node) {
    if (!node) {
        return;
    }

    size_t max = node->gap;

    if (node->rb_left && node->rb_left->subtree_max_gap > max) {
        max = node->rb_left->subtree_max_gap;
    }

    if (node->rb_right && node->rb_right->subtree_max_gap > max) {
        max = node->rb_right->subtree_max_gap;
    }

    node->subtree_max_gap = max;
}

static void vmm_propagate_changes(vm_area_t* node) {
    while (node) {
        size_t old_max = node->subtree_max_gap;
        vmm_recalculate_max_gap(node);

        // If value didn't change, parents won't change either
        if (node->subtree_max_gap == old_max) {
            break;
        }

        node = node->rb_parent;
    }
}

static void rb_rotate_left(vm_space_t* space, vm_area_t* x) {
    vm_area_t* y = x->rb_right;
    x->rb_right  = y->rb_left;

    if (y->rb_left) {
        y->rb_left->rb_parent = x;
    }

    y->rb_parent = x->rb_parent;

    if (!x->rb_parent) {
        space->root = y;
    } else if (x == x->rb_parent->rb_left) {
        x->rb_parent->rb_left = y;
    } else {
        x->rb_parent->rb_right = y;
    }

    y->rb_left   = x;
    x->rb_parent = y;

    // `x` is now a child of `y`, so update `x` first, then `y`
    vmm_recalculate_max_gap(x);
    vmm_recalculate_max_gap(y);
}

static void rb_rotate_right(vm_space_t* space, vm_area_t* y) {
    vm_area_t* x = y->rb_left;
    y->rb_left   = x->rb_right;

    if (x->rb_right) {
        x->rb_right->rb_parent = y;
    }

    x->rb_parent = y->rb_parent;

    if (!y->rb_parent) {
        space->root = x;
    } else if (y == y->rb_parent->rb_left) {
        y->rb_parent->rb_left = x;
    } else {
        y->rb_parent->rb_right = x;
    }

    x->rb_right  = y;
    y->rb_parent = x;

    vmm_recalculate_max_gap(y);
    vmm_recalculate_max_gap(x);
}

static void rb_insert_fixup(vm_space_t* space, vm_area_t* z) {
    while (z->rb_parent && z->rb_parent->rb_color == RB_RED) {
        if (z->rb_parent == z->rb_parent->rb_parent->rb_left) {
            vm_area_t* y = z->rb_parent->rb_parent->rb_right;

            if (y && y->rb_color == RB_RED) {
                z->rb_parent->rb_color            = RB_BLACK;
                y->rb_color                       = RB_BLACK;
                z->rb_parent->rb_parent->rb_color = RB_RED;
                z                                 = z->rb_parent->rb_parent;
            } else {
                if (z == z->rb_parent->rb_right) {
                    z = z->rb_parent;
                    rb_rotate_left(space, z);
                }

                z->rb_parent->rb_color            = RB_BLACK;
                z->rb_parent->rb_parent->rb_color = RB_RED;
                rb_rotate_right(space, z->rb_parent->rb_parent);
            }
        } else {
            vm_area_t* y = z->rb_parent->rb_parent->rb_left;

            if (y && y->rb_color == RB_RED) {
                z->rb_parent->rb_color            = RB_BLACK;
                y->rb_color                       = RB_BLACK;
                z->rb_parent->rb_parent->rb_color = RB_RED;
                z                                 = z->rb_parent->rb_parent;
            } else {
                if (z == z->rb_parent->rb_left) {
                    z = z->rb_parent;
                    rb_rotate_right(space, z);
                }

                z->rb_parent->rb_color            = RB_BLACK;
                z->rb_parent->rb_parent->rb_color = RB_RED;
                rb_rotate_left(space, z->rb_parent->rb_parent);
            }
        }
    }

    space->root->rb_color = RB_BLACK;
}

static void rb_insert(vm_space_t* space, vm_area_t* z) {
    vm_area_t* y = nullptr;
    vm_area_t* x = space->root;

    while (x != nullptr) {
        y = x;

        if (z->start < x->start) {
            x = x->rb_left;
        } else {
            x = x->rb_right;
        }
    }

    z->rb_parent = y;

    if (y == nullptr) {
        space->root = z;
        z->vm_prev = z->vm_next = nullptr;
    } else if (z->start < y->start) {
        y->rb_left = z;

        // If `z` is the left child of `y`, then
        // - y is the immediate successor
        // - y's old predecessor is z's predecessor
        z->vm_next = y;
        z->vm_prev = y->vm_prev;
    } else {
        y->rb_right = z;

        // If `z` is the right child of `y`, then
        // - y is the immediate predecessor
        // - y's old predecessor is z's successor
        z->vm_prev = y;
        z->vm_next = y->vm_next;
    }

    if (z->vm_prev) {
        z->vm_prev->vm_next = z;
    }

    if (z->vm_next) {
        z->vm_next->vm_prev = z;
    }

    // Gap is the space between the previous VMA's end and z's start.
    if (z->vm_prev) {
        z->gap = z->start - z->vm_prev->end;
    } else {
        z->gap = z->start - space->start_limit;
    }

    // Because z is inserted before vm_next, vm_next's gap shrinks
    if (z->vm_next) {
        z->vm_next->gap = z->vm_next->start - z->end;
        vmm_recalculate_max_gap(z->vm_next);
        vmm_propagate_changes(z->vm_next->rb_parent);
    }

    vmm_recalculate_max_gap(z);

    // Propagate z's changes up before rotations
    vmm_propagate_changes(z->rb_parent);

    z->rb_left = z->rb_right = nullptr;
    z->rb_color              = RB_RED;
    rb_insert_fixup(space, z);
}

static vm_area_t* vmm_minimum(vm_area_t* node) {
    while (node->rb_left) {
        node = node->rb_left;
    }

    return node;
}

static int get_color(vm_area_t* node) {
    return node ? node->rb_color : RB_BLACK;
}

// Replaces the subtree rooted at node 'u' with the subtree rooted at node 'v'.
static void rb_transplant(vm_space_t* space, vm_area_t* u, vm_area_t* v) {
    if (!u->rb_parent) {
        space->root = v;
    } else if (u == u->rb_parent->rb_left) {
        u->rb_parent->rb_left = v;
    } else {
        u->rb_parent->rb_right = v;
    }

    if (v) {
        v->rb_parent = u->rb_parent;
    }
}

// Restores RB properties after deletion.
static void rb_delete_fixup(vm_space_t* space, vm_area_t* x, vm_area_t* x_parent) {
    while (x != space->root && get_color(x) == RB_BLACK) {
        if (x == x_parent->rb_left) {
            vm_area_t* w = x_parent->rb_right;

            // Sibling w is RED
            if (get_color(w) == RB_RED) {
                w->rb_color        = RB_BLACK;
                x_parent->rb_color = RB_RED;
                rb_rotate_left(space, x_parent);
                w = x_parent->rb_right;
            }

            // Sibling w is BLACK and both children are BLACK
            if (get_color(w->rb_left) == RB_BLACK && get_color(w->rb_right) == RB_BLACK) {
                if (w) {
                    w->rb_color = RB_RED;
                }

                x        = x_parent;
                x_parent = x->rb_parent;
            } else {
                // Sibling w is BLACK, w->left is RED, w->right is BLACK
                if (get_color(w->rb_right) == RB_BLACK) {
                    if (w->rb_left) {
                        w->rb_left->rb_color = RB_BLACK;
                    }

                    if (w) {
                        w->rb_color = RB_RED;
                    }

                    rb_rotate_right(space, w);
                    w = x_parent->rb_right;
                }

                // Sibling w is BLACK, w->right is RED
                if (w) {
                    w->rb_color = x_parent->rb_color;

                    if (w->rb_right) {
                        w->rb_right->rb_color = RB_BLACK;
                    }
                }

                x_parent->rb_color = RB_BLACK;
                rb_rotate_left(space, x_parent);
                x = space->root;
            }
        } else {
            vm_area_t* w = x_parent->rb_left;

            if (get_color(w) == RB_RED) {
                w->rb_color        = RB_BLACK;
                x_parent->rb_color = RB_RED;
                rb_rotate_right(space, x_parent);
                w = x_parent->rb_left;
            }

            if (get_color(w->rb_right) == RB_BLACK && get_color(w->rb_left) == RB_BLACK) {
                if (w) {
                    w->rb_color = RB_RED;
                }

                x        = x_parent;
                x_parent = x->rb_parent;
            } else {
                if (get_color(w->rb_left) == RB_BLACK) {
                    if (w->rb_right) {
                        w->rb_right->rb_color = RB_BLACK;
                    }

                    if (w) {
                        w->rb_color = RB_RED;
                    }

                    rb_rotate_left(space, w);
                    w = x_parent->rb_left;
                }

                if (w) {
                    w->rb_color = x_parent->rb_color;

                    if (w->rb_left) {
                        w->rb_left->rb_color = RB_BLACK;
                    }
                }

                x_parent->rb_color = RB_BLACK;
                rb_rotate_right(space, x_parent);
                x = space->root;
            }
        }
    }

    if (x) {
        x->rb_color = RB_BLACK;
    }
}

// Removes node 'z' from the tree and restores balance.
static void rb_delete(vm_space_t* space, vm_area_t* z) {
    if (z->vm_prev) {
        z->vm_prev->vm_next = z->vm_next;
    }

    if (z->vm_next) {
        z->vm_next->vm_prev = z->vm_prev;
    }

    if (z->vm_next) {
        if (z->vm_next->vm_prev) {
            z->vm_next->gap = z->vm_next->start - z->vm_next->vm_prev->end;
        } else {
            z->vm_next->gap = z->vm_next->start - space->start_limit;
        }
    }

    vm_area_t* y = z;
    vm_area_t* x;
    vm_area_t* x_parent  = nullptr;
    int y_original_color = y->rb_color;

    if (!z->rb_left) {
        x = z->rb_right;

        // Since z is removed, x connects to z->parent
        x_parent = z->rb_parent;
        rb_transplant(space, z, z->rb_right);
    } else if (!z->rb_right) {
        x        = z->rb_left;
        x_parent = z->rb_parent;
        rb_transplant(space, z, z->rb_left);
    } else {
        // Two children case: Find successor
        y                = vmm_minimum(z->rb_right);
        y_original_color = y->rb_color;
        x                = y->rb_right;

        // If y is the direct child of z
        if (y->rb_parent == z) {
            x_parent = y;
        } else {
            // Save parent before transplant moves y
            x_parent = y->rb_parent;
            rb_transplant(space, y, y->rb_right);
            y->rb_right            = z->rb_right;
            y->rb_right->rb_parent = y;
        }

        rb_transplant(space, z, y);
        y->rb_left            = z->rb_left;
        y->rb_left->rb_parent = y;
        y->rb_color           = z->rb_color;
    }

    if (x_parent) {
        // The structure changed at `x_parent`. Propagate changes up.
        vmm_propagate_changes(x_parent);
    } else if (space->root) {
        // Root changed and has no parent, just update the root
        vmm_recalculate_max_gap(space->root);
    }

    // Earlier, the successor had its gap changed. We must ensure this value is propagated up the
    // tree.
    if (z->vm_next) {
        vmm_recalculate_max_gap(z->vm_next);
        vmm_propagate_changes(z->vm_next->rb_parent);
    }

    if (y_original_color == RB_BLACK) {
        rb_delete_fixup(space, x, x_parent);
    }
}

static bool vmm_is_range_free(vm_space_t* space, uintptr_t start, uintptr_t end) {
    vm_area_t* curr = space->root;

    while (curr) {
        if (start >= curr->end) {
            curr = curr->rb_right;
        } else if (end <= curr->start) {
            curr = curr->rb_left;
        } else {
            return false;
        }
    }

    return true;
}

static bool can_merge_vmas(vm_area_t* left, vm_area_t* right) {
    if (!left || !right) {
        return false;
    }

    if (left->end != right->start) {
        return false;
    }

    if (left->flags != right->flags) {
        return false;
    }

    if (left->cache != right->cache) {
        return false;
    }

    if (left->page_size != right->page_size) {
        return false;
    }

    return true;
}

static void vmm_attempt_merge(vm_space_t* space, vm_area_t* vma) {
    if (vma == nullptr) {
        return;
    }

    vm_area_t* prev = vmm_find_vma(space, vma->start - 1);

    if (can_merge_vmas(prev, vma)) {
        prev->end = vma->end;
        prev->size += vma->size;

        // Remove `vma` since it's now absorbed
        rb_delete(space, vma);
        free_vm_area_struct(vma);

        vma = prev;
    }

    vm_area_t* next = vmm_find_vma(space, vma->end);

    if (can_merge_vmas(prev, vma)) {
        vma->end = next->end;
        vma->size += next->size;

        // Remove `vma` since it's now absorbed
        rb_delete(space, next);
        free_vm_area_struct(next);
    }
}

void vmm_init_space(vm_space_t* space, pagemap_t* map, uintptr_t start, uintptr_t end) {
    space->root        = nullptr;
    space->map         = map;
    space->start_limit = start;
    space->end_limit   = end;

    create_interrupt_lock(&space->lock);
}

vm_area_t* vmm_find_vma(vm_space_t* space, uintptr_t addr) {
    if (space->cached_vma && addr >= space->cached_vma->start && addr < space->cached_vma->end) {
        return space->cached_vma;
    }

    vm_area_t* current = space->root;
    while (current) {
        if (addr >= current->start && addr < current->end) {
            space->cached_vma = current;
            return current;
        }

        if (addr < current->start) {
            current = current->rb_left;
        } else {
            current = current->rb_right;
        }
    }

    return nullptr;
}

static uintptr_t search_gap(
    vm_area_t* node,
    size_t size,
    size_t alignment,
    uintptr_t start_limit,
    uintptr_t end_limit
) {
    if (!node || node->subtree_max_gap < size) {
        return 0;
    }

    // Try Left Subtree
    uintptr_t result = search_gap(node->rb_left, size, alignment, start_limit, end_limit);
    if (result != 0) return result;

    uintptr_t gap_start = node->vm_prev ? node->vm_prev->end : start_limit;
    uintptr_t gap_end   = node->start;

    uintptr_t aligned_start = gap_start;
    if (!is_aligned(aligned_start, alignment)) {
        aligned_start = align_up(aligned_start, alignment);
    }

    // Check bounds and size
    if (aligned_start >= gap_start && aligned_start + size <= gap_end &&
        aligned_start + size <= end_limit) {
        return aligned_start;
    }

    // Try Right Subtree
    return search_gap(node->rb_right, size, alignment, start_limit, end_limit);
}

static uintptr_t find_free_region(vm_space_t* space, size_t size, size_t alignment) {
    if (!space->root) {
        uintptr_t candidate = space->start_limit;

        if (!is_aligned(candidate, alignment)) {
            candidate = align_up(candidate, alignment);
        }

        if (candidate + size <= space->end_limit) {
            return candidate;
        }

        return 0;
    }

    uintptr_t addr = search_gap(space->root, size, alignment, space->start_limit, space->end_limit);

    if (addr) {
        return addr;
    }

    // The tree search covers all gaps between nodes. It doesn't cover the space after the
    // right-most node.
    vm_area_t* last = space->root;

    while (last->rb_right) {
        last = last->rb_right;
    }

    uintptr_t tail_start = last->end;

    if (!is_aligned(tail_start, alignment)) {
        tail_start = align_up(tail_start, alignment);
    }

    if (tail_start + size <= space->end_limit) {
        return tail_start;
    }

    return 0;
}

void* vmm_alloc(
    vm_space_t* space,
    size_t size,
    uint32_t flags,
    cache_type_t cache,
    size_t page_size
) {
    void* ret = nullptr;

    acquire_interrupt_lock(&space->lock);

    if (size == 0) {
        goto cleanup;
    }

    if (page_size == 0) {
        page_size = PAGE_SIZE_SMALL;
    }

    if (!is_aligned(size, page_size)) {
        size = align_up(size, page_size);
    }

    uintptr_t addr = 0;

    if (flags & VMM_FLAG_STACK) {
        // We start seaching at the top of the address space
        uintptr_t candidate = space->end_limit;

        // Initial Alignment (Round down to page align)
        if (!is_aligned(candidate, page_size)) {
            candidate = align_down(candidate, page_size);
        }

        // Adjust for size
        candidate -= size;

        while (candidate >= space->start_limit) {
            // Check for collision
            vm_area_t* overlap = vmm_find_vma(space, candidate);

            if (!overlap) {
                overlap = vmm_find_vma(space, candidate + size - 1);
            }

            // Found a valid hole
            if (!overlap) {
                addr = candidate;
                break;
            }

            candidate = overlap->start;

            if (!is_aligned(candidate, page_size)) {
                candidate = align_down(candidate, page_size);
            }

            candidate -= size;
        }
    } else {
        addr = find_free_region(space, size, page_size);
    }

    if (!addr) {
        errno = ENOMEM;

        KLOG_WARN(
            "VMM: no free region size=0x%zx align=0x%zx in [%lx,%lx)\n",
            size,
            page_size,
            space->start_limit,
            space->end_limit
        );

        goto cleanup;
    }

    vm_area_t* vma = alloc_vm_area_struct();
    if (!vma) {
        if (errno == 0) {
            errno = ENOMEM;
        }

        KLOG_ERROR("VMM: failed to allocate VMA struct\n");
        goto cleanup;
    }

    vma->start     = addr;
    vma->end       = addr + size;
    vma->size      = size;
    vma->flags     = (flags & VMM_FLAG_MMIO) ? VMM_FLAG_NONE : flags;
    vma->cache     = cache;
    vma->page_size = page_size;

    rb_insert(space, vma);

    if (flags & VMM_FLAG_STACK) {
        // Create a separate VMA for the guard page (Do not map it to the pagemap)
        uintptr_t guard_addr = addr - PAGE_SIZE_SMALL;

        vm_area_t* guard = alloc_vm_area_struct();
        guard->start     = guard_addr;
        guard->end       = addr;
        guard->size      = PAGE_SIZE_SMALL;
        guard->flags     = VMM_FLAG_NONE;  // No Read, No Write -> Segfault on access

        rb_insert(space, guard);
    }

    // MMIO pages must be explicitly mapped by the user
    if ((flags & VMM_FLAG_DEMAND) || (flags & VMM_FLAG_MMIO)) {
        ret = (void*)addr;
        goto cleanup;
    }

    size_t frames_per_page = page_size / PAGE_SIZE_SMALL;

    // If the new allocation is not Shared, Standard 4K page, and Zero page is initialized then, map
    // everything to the single shared zero page as Read-Only.
    bool zero_page =
        (flags & VMM_FLAG_PRIVATE) && (page_size == PAGE_SIZE_SMALL) && (shared_zero_page != 0);

    if (zero_page) {
        flags &= ~VMM_FLAG_WRITE;

        for (uintptr_t curr = addr; curr < (addr + size); curr += page_size) {
            pagemap_map_args_t margs = {
                .virt_addr  = (void*)curr,
                .phys_addr  = (void*)shared_zero_page,
                .length     = page_size,
                .flags      = flags,
                .cache      = cache,
                .page_size  = (uint32_t)page_size,
                .skip_flush = false,
            };

            if (!pagemap_map(space->map, margs)) {
                if (errno == 0) {
                    errno = EFAULT;
                }

                KLOG_WARN(
                    "VMM: zero-page map failed virt=0x%lx len=0x%zx errno=%d\n",
                    curr,
                    page_size,
                    errno
                );

                for (uintptr_t cleanup = addr; cleanup < curr; cleanup += page_size) {
                    pagemap_unmap_args_t uargs = {
                        .virt_addr = (void*)cleanup,
                        .length    = page_size,
                    };

                    pagemap_unmap(space->map, uargs);
                    pmm_dec_ref((void*)shared_zero_page);
                }

                rb_delete(space, vma);
                free_vm_area_struct(vma);
                release_interrupt_lock(&space->lock);
                return nullptr;
            }

            pmm_inc_ref((void*)shared_zero_page);
        }
    } else {
        for (uintptr_t curr = addr; curr < (addr + size); curr += page_size) {
            void* phys = pmm_alloc_aligned(page_size, frames_per_page);

            if (!phys) {
                errno = ENOMEM;
                KLOG_WARN(
                    "VMM: alloc phys failed virt=0x%lx size=0x%zx align=0x%zx\n",
                    curr,
                    page_size,
                    page_size
                );

                for (uintptr_t cleanup = addr; cleanup < curr; cleanup += page_size) {
                    uintptr_t p = pagemap_translate(space->map, cleanup);

                    if (p) {
                        pagemap_unmap_args_t uargs = {
                            .virt_addr = (void*)cleanup,
                            .length    = page_size,
                        };

                        pagemap_unmap(space->map, uargs);
                        pmm_free((void*)p, frames_per_page);
                    }
                }

                rb_delete(space, vma);
                free_vm_area_struct(vma);
                release_interrupt_lock(&space->lock);
                return nullptr;
            }

            pagemap_map_args_t margs = {
                .virt_addr  = (void*)curr,
                .phys_addr  = phys,
                .length     = page_size,
                .flags      = flags,
                .cache      = cache,
                .page_size  = (uint32_t)page_size,
                .skip_flush = false,
            };

            if (!pagemap_map(space->map, margs)) {
                if (errno == 0) {
                    errno = EFAULT;
                }

                KLOG_WARN(
                    "VMM: map failed virt=0x%lx phys=%p len=0x%zx errno=%d\n",
                    curr,
                    phys,
                    page_size,
                    errno
                );

                pmm_free(phys, frames_per_page);

                for (uintptr_t cleanup = addr; cleanup < curr; cleanup += page_size) {
                    uintptr_t p = pagemap_translate(space->map, cleanup);

                    if (p) {
                        pagemap_unmap_args_t uargs = {
                            .virt_addr = (void*)cleanup,
                            .length    = page_size,
                        };

                        pagemap_unmap(space->map, uargs);
                        pmm_free((void*)p, frames_per_page);
                    }
                }

                rb_delete(space, vma);
                free_vm_area_struct(vma);
                release_interrupt_lock(&space->lock);
                return nullptr;
            }
        }
    }

    ret = (void*)addr;
cleanup:
    vmm_attempt_merge(space, vma);
    release_interrupt_lock(&space->lock);
    return ret;
}

void* vmm_alloc_at(
    vm_space_t* space,
    void* ptr,
    size_t size,
    uint32_t flags,
    cache_type_t cache,
    size_t page_size
) {
    uintptr_t addr = (uintptr_t)ptr;
    void* ret      = nullptr;

    acquire_interrupt_lock(&space->lock);

    if (size == 0) {
        goto cleanup;
    }

    if (page_size == 0) {
        page_size = PAGE_SIZE_SMALL;
    }

    if (!is_aligned(size, page_size)) {
        size = align_up(size, page_size);
    }

    uintptr_t end_addr = addr + size;

    if (addr < space->start_limit || end_addr > space->end_limit) {
        goto cleanup;
    }

    if (!vmm_is_range_free(space, addr, end_addr)) {
        goto cleanup;
    }

    vm_area_t* vma = alloc_vm_area_struct();

    if (!vma) {
        if (errno == 0) {
            errno = ENOMEM;
        }

        KLOG_ERROR("VMM: failed to allocate VMA struct\n");
        goto cleanup;
    }

    vma->start     = addr;
    vma->end       = end_addr;
    vma->size      = size;
    vma->flags     = (flags & VMM_FLAG_MMIO) ? VMM_FLAG_NONE : flags;
    vma->cache     = cache;
    vma->page_size = page_size;
    vma->next_free = nullptr;

    rb_insert(space, vma);

    if (flags & VMM_FLAG_STACK) {
        // Create a separate VMA for the guard page (Do not map it to the pagemap)
        uintptr_t guard_addr = addr - PAGE_SIZE_SMALL;

        vm_area_t* guard = alloc_vm_area_struct();
        guard->start     = guard_addr;
        guard->end       = addr;
        guard->size      = PAGE_SIZE_SMALL;
        guard->flags     = VMM_FLAG_NONE;  // No Read, No Write -> Segfault on access

        rb_insert(space, guard);
    }

    // MMIO pages must be explicitly mapped by the user
    if ((flags & VMM_FLAG_DEMAND) || (flags & VMM_FLAG_MMIO)) {
        ret = (void*)addr;
        goto cleanup;
    }

    size_t frames_per_page = page_size / PAGE_SIZE_SMALL;

    // If the new allocation is not Shared, Standard 4K page, and Zero page is initialized then, map
    // everything to the single shared zero page as Read-Only.
    bool zero_page =
        (flags & VMM_FLAG_PRIVATE) && (page_size == PAGE_SIZE_SMALL) && (shared_zero_page != 0);

    if (zero_page) {
        flags &= ~VMM_FLAG_WRITE;

        for (uintptr_t curr = addr; curr < (addr + size); curr += page_size) {
            pagemap_map_args_t margs = {
                .virt_addr  = (void*)curr,
                .phys_addr  = (void*)shared_zero_page,
                .length     = page_size,
                .flags      = flags,
                .cache      = cache,
                .page_size  = (uint32_t)page_size,
                .skip_flush = false,
            };

            if (!pagemap_map(space->map, margs)) {
                if (errno == 0) {
                    errno = EFAULT;
                }

                KLOG_WARN(
                    "VMM: zero-page map failed virt=0x%lx len=0x%zx errno=%d\n",
                    curr,
                    page_size,
                    errno
                );

                for (uintptr_t cleanup = addr; cleanup < curr; cleanup += page_size) {
                    pagemap_unmap_args_t uargs = {
                        .virt_addr = (void*)cleanup,
                        .length    = page_size,
                    };

                    pagemap_unmap(space->map, uargs);
                    pmm_dec_ref((void*)shared_zero_page);
                }

                rb_delete(space, vma);
                free_vm_area_struct(vma);
                release_interrupt_lock(&space->lock);
                return nullptr;
            }

            pmm_inc_ref((void*)shared_zero_page);
        }
    } else {
        for (uintptr_t curr = addr; curr < (addr + size); curr += page_size) {
            void* phys = pmm_alloc_aligned(page_size, frames_per_page);

            if (!phys) {
                errno = ENOMEM;
                KLOG_WARN(
                    "VMM: alloc phys failed virt=0x%lx size=0x%zx align=0x%zx\n",
                    curr,
                    page_size,
                    page_size
                );

                for (uintptr_t cleanup = addr; cleanup < curr; cleanup += page_size) {
                    uintptr_t p = pagemap_translate(space->map, cleanup);

                    if (p) {
                        pagemap_unmap_args_t uargs = {
                            .virt_addr = (void*)cleanup,
                            .length    = page_size,
                        };

                        pagemap_unmap(space->map, uargs);
                        pmm_free((void*)p, frames_per_page);
                    }
                }

                rb_delete(space, vma);
                free_vm_area_struct(vma);
                release_interrupt_lock(&space->lock);
                return nullptr;
            }

            pagemap_map_args_t margs = {
                .virt_addr  = (void*)curr,
                .phys_addr  = phys,
                .length     = page_size,
                .flags      = flags,
                .cache      = cache,
                .page_size  = (uint32_t)page_size,
                .skip_flush = false,
            };

            if (!pagemap_map(space->map, margs)) {
                if (errno == 0) {
                    errno = EFAULT;
                }

                KLOG_WARN(
                    "VMM: map failed virt=0x%lx phys=%p len=0x%zx errno=%d\n",
                    curr,
                    phys,
                    page_size,
                    errno
                );

                pmm_free(phys, frames_per_page);

                for (uintptr_t cleanup = addr; cleanup < curr; cleanup += page_size) {
                    uintptr_t p = pagemap_translate(space->map, cleanup);

                    if (p) {
                        pagemap_unmap_args_t uargs = {
                            .virt_addr = (void*)cleanup,
                            .length    = page_size,
                        };

                        pagemap_unmap(space->map, uargs);
                        pmm_free((void*)p, frames_per_page);
                    }
                }

                rb_delete(space, vma);
                free_vm_area_struct(vma);
                release_interrupt_lock(&space->lock);
                return nullptr;
            }
        }
    }

    ret = (void*)addr;

cleanup:
    vmm_attempt_merge(space, vma);
    release_interrupt_lock(&space->lock);
    return ret;
}

void vmm_free(vm_space_t* space, void* ptr, size_t size) {
    acquire_interrupt_lock(&space->lock);
    uintptr_t start = (uintptr_t)ptr;
    uintptr_t end   = start + size;

    bool free_vma = false;

    vm_area_t* vma = vmm_find_vma(space, start);

    if (!vma || start < vma->start || end > vma->end) {
        errno = EINVAL;
        KLOG_WARN("VMM: free invalid addr=0x%lx\n", start);
        goto cleanup;
    }

    if (!is_aligned(start, vma->page_size) || !is_aligned(size, vma->page_size)) {
        errno = EINVAL;
        KLOG_WARN(
            "VMM: free unaligned start=0x%lx size=0x%lx page_size=0x%lx\n",
            start,
            size,
            vma->page_size
        );
        goto cleanup;
    }

    if (space->cached_vma == vma) {
        space->cached_vma = nullptr;
    }

    if (start == vma->start && end == vma->end) {
        // Freeing the entire VMA
        rb_delete(space, vma);
        free_vma = true;
    } else if (start == vma->start) {
        // Freeing the head (shrink from start)
        rb_delete(space, vma);

        vma->start = end;
        vma->size  = vma->end - vma->start;

        rb_insert(space, vma);
    } else if (end == vma->end) {
        // Freeing the tail
        vma->end  = start;
        vma->size = vma->end - vma->start;
        rb_insert_fixup(space, vma);
    } else {
        // Split the VMA into two
        vm_area_t* right = alloc_vm_area_struct();

        if (!right) {
            errno = ENOMEM;
            goto cleanup;
        }

        // Copy properties to right split
        *right         = *vma;
        right->start   = end;
        right->end     = vma->end;
        right->size    = right->end - right->start;
        right->rb_left = right->rb_right = right->rb_parent = nullptr;

        // Shrink current VMA to be the left split
        vma->end  = start;
        vma->size = vma->end - vma->start;

        rb_insert(space, right);
    }

    // Unmap Physical Pages
    for (uintptr_t virt = start; virt < end; virt += vma->page_size) {
        uintptr_t phys = pagemap_translate(space->map, virt);

        if (phys) {
            pagemap_unmap_args_t u_args = {
                .virt_addr = (void*)virt,
                .length    = vma->page_size,
            };

            pagemap_unmap(space->map, u_args);
            pmm_free((void*)phys, vma->page_size / PAGE_SIZE_SMALL);
        } else {
            errno = EFAULT;
            KLOG_WARN("VMM: free translate failed virt=0x%lx\n", virt);
        }
    }

    if (free_vma) {
        free_vm_area_struct(vma);
    }

    vmm_propagate_changes(vma);
cleanup:
    release_interrupt_lock(&space->lock);
}