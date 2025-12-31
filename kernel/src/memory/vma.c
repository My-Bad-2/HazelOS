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

        if (!is_aligned(start, _Alignof(vm_area_t)) != 0) {
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
    } else if (z->start < y->start) {
        y->rb_left = z;
    } else {
        y->rb_right = z;
    }

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

void vmm_init_space(vm_space_t* space, pagemap_t* map, uintptr_t start, uintptr_t end) {
    space->root        = nullptr;
    space->map         = map;
    space->start_limit = start;
    space->end_limit   = end;
    space->alloc_hint  = start;

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

static uintptr_t find_free_region(vm_space_t* space, size_t size, size_t alignment) {
    uintptr_t candidate = space->alloc_hint;

    // Clamp to start limit
    if (candidate < space->start_limit) {
        candidate = space->start_limit;
    }

    if (!is_aligned(candidate, alignment)) {
        candidate = align_up(candidate, alignment);
    }

    int loop_count = 0;

    while (true) {
        if (candidate + size > space->end_limit) {
            // Wrap around once
            if (loop_count == 0) {
                candidate = space->start_limit;

                if (!is_aligned(candidate, alignment)) {
                    candidate = align_up(candidate, alignment);
                }

                loop_count++;
                continue;
            }

            return 0;
        }

        // Check for collision
        vm_area_t* overlap = vmm_find_vma(space, candidate);

        if (!overlap) {
            overlap = vmm_find_vma(space, candidate + size - 1);
        }

        if (!overlap) {
            // Valid gap found
            space->alloc_hint = candidate + size;
            return candidate;
        }

        // Collision: Jump over the VMA
        candidate = overlap->end;

        if (!is_aligned(candidate, alignment)) {
            candidate += (alignment - (candidate % alignment));
        }
    }

    return 0;
}

void* vmm_alloc(
    vm_space_t* space,
    size_t size,
    uint32_t flags,
    cache_type_t cache,
    size_t alignment
) {
    void* ret = nullptr;

    acquire_interrupt_lock(&space->lock);

    if (size == 0) {
        goto cleanup;
    }

    if (alignment == 0) {
        alignment = PAGE_SIZE_SMALL;
    }

    if (!is_aligned(size, alignment)) {
        size = align_up(size, alignment);
    }

    uintptr_t addr = 0;

    if (flags & VMM_FLAG_STACK) {
        // We start seaching at the top of the address space
        uintptr_t candidate = space->end_limit;

        // Initial Alignment (Round down to page align)
        if (!is_aligned(candidate, alignment)) {
            candidate = align_down(candidate, alignment);
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

            if (!is_aligned(candidate, alignment)) {
                candidate = align_down(candidate, alignment);
            }

            candidate -= size;
        }
    } else {
        addr = find_free_region(space, size, alignment);
    }

    if (!addr) {
        errno = ENOMEM;

        KLOG_WARN(
            "VMM: no free region size=0x%zx align=0x%zx in [%lx,%lx)\n",
            size,
            alignment,
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
    vma->page_size = alignment;

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

    size_t frames_per_page = alignment / PAGE_SIZE_SMALL;

    // If the new allocation is not Shared, Standard 4K page, and Zero page is initialized then, map
    // everything to the single shared zero page as Read-Only.
    bool zero_page =
        (flags & VMM_FLAG_PRIVATE) && (alignment == PAGE_SIZE_SMALL) && (shared_zero_page != 0);

    if (zero_page) {
        flags &= ~VMM_FLAG_WRITE;

        for (uintptr_t curr = addr; curr < (addr + size); curr += alignment) {
            pagemap_map_args_t margs = {
                .virt_addr  = (void*)curr,
                .phys_addr  = (void*)shared_zero_page,
                .length     = alignment,
                .flags      = flags,
                .cache      = cache,
                .page_size  = (uint32_t)alignment,
                .skip_flush = false,
            };

            if (!pagemap_map(space->map, margs)) {
                if (errno == 0) {
                    errno = EFAULT;
                }

                KLOG_WARN(
                    "VMM: zero-page map failed virt=0x%lx len=0x%zx errno=%d\n",
                    curr,
                    alignment,
                    errno
                );

                for (uintptr_t cleanup = addr; cleanup < curr; cleanup += alignment) {
                    pagemap_unmap_args_t uargs = {
                        .virt_addr = (void*)cleanup,
                        .length    = alignment,
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
        for (uintptr_t curr = addr; curr < (addr + size); curr += alignment) {
            void* phys = pmm_alloc_aligned(alignment, frames_per_page);

            if (!phys) {
                errno = ENOMEM;
                KLOG_WARN(
                    "VMM: alloc phys failed virt=0x%lx size=0x%zx align=0x%zx\n",
                    curr,
                    alignment,
                    alignment
                );

                for (uintptr_t cleanup = addr; cleanup < curr; cleanup += alignment) {
                    uintptr_t p = pagemap_translate(space->map, cleanup);

                    if (p) {
                        pagemap_unmap_args_t uargs = {
                            .virt_addr = (void*)cleanup,
                            .length    = alignment,
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
                .length     = alignment,
                .flags      = flags,
                .cache      = cache,
                .page_size  = (uint32_t)alignment,
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
                    alignment,
                    errno
                );

                pmm_free(phys, frames_per_page);

                for (uintptr_t cleanup = addr; cleanup < curr; cleanup += alignment) {
                    uintptr_t p = pagemap_translate(space->map, cleanup);

                    if (p) {
                        pagemap_unmap_args_t uargs = {
                            .virt_addr = (void*)cleanup,
                            .length    = alignment,
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
    release_interrupt_lock(&space->lock);
    return ret;
}

void* vmm_alloc_at(
    vm_space_t* space,
    void* ptr,
    size_t size,
    uint32_t flags,
    cache_type_t cache,
    size_t alignment
) {
    uintptr_t addr = (uintptr_t)ptr;
    void* ret      = nullptr;

    acquire_interrupt_lock(&space->lock);

    if (size == 0) {
        goto cleanup;
    }

    if (alignment == 0) {
        alignment = PAGE_SIZE_SMALL;
    }

    if (!is_aligned(size, alignment)) {
        size = align_up(size, alignment);
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
    vma->page_size = alignment;
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

    size_t frames_per_page = alignment / PAGE_SIZE_SMALL;

    // If the new allocation is not Shared, Standard 4K page, and Zero page is initialized then, map
    // everything to the single shared zero page as Read-Only.
    bool zero_page =
        (flags & VMM_FLAG_PRIVATE) && (alignment == PAGE_SIZE_SMALL) && (shared_zero_page != 0);

    if (zero_page) {
        flags &= ~VMM_FLAG_WRITE;

        for (uintptr_t curr = addr; curr < (addr + size); curr += alignment) {
            pagemap_map_args_t margs = {
                .virt_addr  = (void*)curr,
                .phys_addr  = (void*)shared_zero_page,
                .length     = alignment,
                .flags      = flags,
                .cache      = cache,
                .page_size  = (uint32_t)alignment,
                .skip_flush = false,
            };

            if (!pagemap_map(space->map, margs)) {
                if (errno == 0) {
                    errno = EFAULT;
                }

                KLOG_WARN(
                    "VMM: zero-page map failed virt=0x%lx len=0x%zx errno=%d\n",
                    curr,
                    alignment,
                    errno
                );

                for (uintptr_t cleanup = addr; cleanup < curr; cleanup += alignment) {
                    pagemap_unmap_args_t uargs = {
                        .virt_addr = (void*)cleanup,
                        .length    = alignment,
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
        for (uintptr_t curr = addr; curr < (addr + size); curr += alignment) {
            void* phys = pmm_alloc_aligned(alignment, frames_per_page);

            if (!phys) {
                errno = ENOMEM;
                KLOG_WARN(
                    "VMM: alloc phys failed virt=0x%lx size=0x%zx align=0x%zx\n",
                    curr,
                    alignment,
                    alignment
                );

                for (uintptr_t cleanup = addr; cleanup < curr; cleanup += alignment) {
                    uintptr_t p = pagemap_translate(space->map, cleanup);

                    if (p) {
                        pagemap_unmap_args_t uargs = {
                            .virt_addr = (void*)cleanup,
                            .length    = alignment,
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
                .length     = alignment,
                .flags      = flags,
                .cache      = cache,
                .page_size  = (uint32_t)alignment,
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
                    alignment,
                    errno
                );

                pmm_free(phys, frames_per_page);

                for (uintptr_t cleanup = addr; cleanup < curr; cleanup += alignment) {
                    uintptr_t p = pagemap_translate(space->map, cleanup);

                    if (p) {
                        pagemap_unmap_args_t uargs = {
                            .virt_addr = (void*)cleanup,
                            .length    = alignment,
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
    release_interrupt_lock(&space->lock);
    return ret;
}

void vmm_free(vm_space_t* space, void* ptr) {
    acquire_interrupt_lock(&space->lock);
    uintptr_t addr = (uintptr_t)ptr;

    vm_area_t* vma = vmm_find_vma(space, addr);

    if (!vma || vma->start != addr) {
        errno = EINVAL;
        KLOG_WARN("VMM: free invalid addr=0x%lx\n", addr);
        goto cleanup;
    }

    if (space->cached_vma == vma) {
        space->cached_vma = nullptr;
    }

    // Remove from Tree
    rb_delete(space, vma);

    // Unmap Physical Pages
    for (uintptr_t virt = vma->start; virt < vma->end; virt += vma->page_size) {
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

    free_vm_area_struct(vma);
cleanup:
    release_interrupt_lock(&space->lock);
}