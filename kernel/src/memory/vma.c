#include "memory/vma.h"

#include <errno.h>
#include <stdint.h>
#include <string.h>

#include "libs/log.h"
#include "libs/math.h"
#include "libs/spinlock.h"
#include "memory/memory.h"
#include "memory/pagemap.h"
#include "memory/pmm.h"

#define RB_BLACK 0
#define RB_RED   1

vm_space_t kernel_space;
uintptr_t shared_zero_page = 0;

typedef struct vma_slab_page {
    struct vma_slab_page* next;
} vma_slab_page_t;

static struct {
    vm_area_t* free_list;
    vma_slab_page_t* pages;
    interrupt_lock_t lock;
} vma_slab;

void vmm_init_global(void) {
    vma_slab.free_list = nullptr;
    vma_slab.pages     = nullptr;
    create_interrupt_lock(&vma_slab.lock);

    void* ptr = pmm_alloc(1);
    if (!ptr) {
        errno = ENOMEM;
        KLOG_ERROR("VMM: failed to allocate shared zero page\n");
        return;
    }

    memset((void*)to_higher_half((uintptr_t)ptr), 0, PAGE_SIZE_SMALL);

    shared_zero_page = (uintptr_t)ptr;
}

static vm_area_t* alloc_vm_area_struct() {
    acquire_interrupt_lock(&vma_slab.lock);

    // Use existing free object
    if (vma_slab.free_list) {
        vm_area_t* obj     = vma_slab.free_list;
        vma_slab.free_list = obj->next_free;
        release_interrupt_lock(&vma_slab.lock);
        return obj;
    }

    // Allocate new page from PMM
    void* p = pmm_alloc(1);
    if (!p) {
        errno = ENOMEM;
        KLOG_ERROR("VMM: failed to allocate VMA slab page\n");
        release_interrupt_lock(&vma_slab.lock);
        return nullptr;
    }

    void* page = (void*)to_higher_half((uintptr_t)p);

    // Add to page tracker
    vma_slab_page_t* header = (vma_slab_page_t*)page;
    header->next            = vma_slab.pages;
    vma_slab.pages          = header;

    // Slice the rest of the page into vm_area_t
    // Start after the header
    uintptr_t cursor = (uintptr_t)page + sizeof(vma_slab_page_t);
    uintptr_t end    = (uintptr_t)page + PAGE_SIZE_SMALL;

    vm_area_t* first = (vm_area_t*)cursor;
    vm_area_t* curr  = first;

    cursor += sizeof(vm_area_t);

    while (cursor + sizeof(vm_area_t) <= end) {
        vm_area_t* next = (vm_area_t*)cursor;
        curr->next_free = next;
        curr            = next;

        cursor += sizeof(vm_area_t);
    }

    curr->next_free = nullptr;

    vma_slab.free_list = first->next_free;

    release_interrupt_lock(&vma_slab.lock);
    return first;
}

static void free_vm_area_struct(vm_area_t* ptr) {
    acquire_interrupt_lock(&vma_slab.lock);
    ptr->next_free     = vma_slab.free_list;
    vma_slab.free_list = ptr;
    release_interrupt_lock(&vma_slab.lock);
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
    return NULL;
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

    if (alignment == 0) {
        alignment = PAGE_SIZE_SMALL;
    }

    if (!is_aligned(size, alignment)) {
        size = align_up(size, alignment);
    }

    uintptr_t addr = find_free_region(space, size, alignment);

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
    vma->flags     = flags;
    vma->cache     = cache;
    vma->page_size = alignment;

    rb_insert(space, vma);

    if (flags & VMM_FLAG_DEMAND) {
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
        space->cached_vma = NULL;
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