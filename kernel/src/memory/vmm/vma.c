#include "memory/vma.h"

#include <stdatomic.h>
#include <stdint.h>
#include <string.h>

#include "compiler.h"
#include "core/capability.h"
#include "core/errors.h"
#include "libs/kobject.h"
#include "libs/log.h"
#include "libs/math.h"
#include "libs/spinlock.h"
#include "memory/heap.h"
#include "memory/memory.h"
#include "memory/pagemap.h"
#include "memory/vm_object.h"
#include "memory/vmm.h"

#include "../internal/vma_tree.h"

#define max(a, b) ((a) > (b) ? (a) : (b))
#define min(a, b) ((a) < (b) ? (a) : (b))

static struct vm_space kspace;
struct vm_space* kernel_space      = &kspace;
kmem_cache_t* vma_cache            = nullptr;
static kmem_cache_t* vmspace_cache = nullptr;

static void vmm_free_pending_vmas(struct vm_area* allocated_vma, struct vm_area* allocated_guard) {
    if (allocated_vma) kmem_cache_free(vma_cache, allocated_vma);
    if (allocated_guard) kmem_cache_free(vma_cache, allocated_guard);
}

static struct vm_area* vmm_find_next_vma_after_unsafe(struct vm_space* space, uintptr_t addr) {
    struct rb_node* node = space->rb_root.rb_node;
    struct vm_area* next = nullptr;

    while (node) {
        struct vm_area* curr = rb_entry(node, struct vm_area, rb_node);

        if (curr->start > addr) {
            next = curr;
            node = node->rb_left;
        } else {
            node = node->rb_right;
        }
    }

    return next;
}

static void vmm_remove_stack_guard_if_present(struct vm_space* space, struct vm_area* vma) {
    if (!(vma->flags & VMM_FLAG_STACK)) return;

    struct rb_node* prev = rb_prev(&vma->rb_node);
    if (!prev) return;

    struct vm_area* guard = rb_entry(prev, struct vm_area, rb_node);
    if (guard->flags != VMM_FLAG_GUARD || guard->end != vma->start) return;

    rb_erase_augmented(&guard->rb_node, &space->rb_root, vma_compute_subtree_gap);
    kmem_cache_free(vma_cache, guard);
}

void vma_cache_init(void) {
    vma_cache = kmem_cache_create(
        "vma_cache",
        sizeof(struct vm_area),
        _Alignof(struct vm_area),
        SLAB_NEVER_MERGE,
        nullptr
    );

    vmspace_cache = kmem_cache_create(
        "vmspace_cache",
        sizeof(struct vm_space),
        _Alignof(struct vm_space),
        SLAB_NEVER_MERGE | SLAB_HWCACHE_ALIGN,
        nullptr
    );

    vm_object_init();
}

void vmm_init_space(struct vm_space* space, bool is_kernel) {
    memset(space, 0, sizeof(struct vm_space));
    space->rb_root         = RB_ROOT;
    space->map             = is_kernel ? vmm_get_kernel_pagemap() : pagemap_create();
    space->allocation_hint = is_kernel ? get_kernel_space_start_limit() : USER_SPACE_START;

    atomic_init(&space->cached_vma, nullptr);
    create_rwlock(&space->lock);
    kref_init(&space->refcount, CAP_TYPE_VSPACE);
}

struct vm_space* vmm_create_space(bool is_kernel) {
    struct vm_space* space = kmem_cache_alloc(vmspace_cache);
    if (!space) return nullptr;

    vmm_init_space(space, is_kernel);
    return space;
}

void vmm_space_release(struct kobject* ref) {
    struct vm_space* space = kref_entry(ref, struct vm_space, refcount);
    if (unlikely(space->map == vmm_get_kernel_pagemap()))
        PANIC("VMM: Attempted to destroy Kernel VSpace!");

    vmm_destroy_space(space);
    pagemap_release(space->map);
    kmem_cache_free(vmspace_cache, space);
}

static uint8_t select_page_shift(size_t size, uintptr_t addr) {
    if (size >= PAGE_SIZE_LARGE && (size % PAGE_SIZE_LARGE == 0) && (addr % PAGE_SIZE_LARGE == 0))
        return PAGE_SHIFT_LARGE;

    if (size >= PAGE_SIZE_MEDIUM && (size % PAGE_SIZE_MEDIUM == 0) &&
        (addr % PAGE_SIZE_MEDIUM == 0))
        return PAGE_SHIFT_MEDIUM;

    return PAGE_SHIFT_SMALL;
}

static void
vmm_unmap_hardware_range(struct vm_space* space, uintptr_t start, size_t size, uint8_t page_shift) {
    uintptr_t addr   = start;
    uintptr_t end    = start + size;
    size_t page_size = 1ul << page_shift;

    if (unlikely(!space->map)) return;

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

bool vmm_populate_vma_range(
    struct vm_space* space,
    struct vm_area* vma,
    uintptr_t start,
    size_t size
) {
    if (vma->flags & VMM_FLAG_GUARD) return true;
    if ((vma->flags & VMM_FLAG_DEMAND) && !(vma->flags & VMM_FLAG_POPULATE)) return true;
    if (unlikely(!space->map)) return false;

    uintptr_t addr   = start;
    uintptr_t end    = start + size;
    size_t page_size = vma_page_size(vma);

    uint32_t pte_flags = vma->flags;
    if (vma->flags & VMM_FLAG_COW) pte_flags &= ~VMM_FLAG_WRITE;

    cache_type_t cache = (vma->flags & VMM_FLAG_MMIO) ? CACHE_UNCACHEABLE : vma->cache;
    while (addr < end) {
        size_t object_offset = vma->object_offset + (addr - vma->start);

        uintptr_t phys = 0;
        int status =
            vm_object_get_page(vma->object, object_offset, vma->page_shift, true, true, &phys);

        if (unlikely(status != ERR_OK)) {
            if (status == ERR_AGAIN) return true;
            if (addr > start) vmm_unmap_hardware_range(space, start, addr - start, vma->page_shift);
            return false;
        }

        pagemap_map_args_t args = {
            .virt_addr = (void*)addr,
            .phys_addr = (void*)phys,
            .length    = page_size,
            .flags     = pte_flags,
            .cache     = cache,
            .page_size = page_size,
        };

        if (unlikely(!pagemap_map(space->map, &args))) {
            if (addr > start) vmm_unmap_hardware_range(space, start, addr - start, vma->page_shift);
            return false;
        }

        addr += page_size;
    }

    return true;
}

void* vmalloc(
    struct vm_space* space,
    void* hint_addr,
    size_t size,
    uint32_t flags,
    cache_type_t cache,
    size_t alignment,
    struct vm_object* vmo,
    size_t vmo_offset
) {
    if (unlikely(size == 0)) return nullptr;

    const bool is_stack = (flags & VMM_FLAG_STACK) != 0;
    if (unlikely(!vmo && !is_stack && !(flags & VMM_FLAG_GUARD))) {
        KLOG_ERROR("VMM: Attempted to map memory without a backing VMO.");
        return nullptr;
    }

    alignment = max(alignment, PAGE_SIZE_SMALL);
    size      = align_up(size, PAGE_SIZE_SMALL);

    const bool is_fixed = (flags & VMM_FLAG_FIXED) || (flags & VMM_FLAG_FIXED_NOREPLACE);
    if (unlikely(is_fixed && !hint_addr)) return nullptr;

    size_t actual_size  = size + (is_stack ? PAGE_SIZE_SMALL : 0);
    uintptr_t addr      = (uintptr_t)hint_addr;
    uint8_t final_shift = select_page_shift(size, addr);
    size_t align        = max(1ul << final_shift, alignment);

    const bool is_kernel = (space->map == vmm_get_kernel_pagemap());
    uintptr_t safe_start = is_kernel ? get_kernel_space_start_limit() : USER_SPACE_START;
    uintptr_t safe_end   = is_kernel ? KERNEL_SPACE_END : get_user_space_end_limit();

    if (unlikely(
            is_fixed &&
            (!is_aligned(addr, alignment) || addr < safe_start || addr + actual_size > safe_end)
        ))
        return nullptr;

    acquire_write(&space->lock);

    struct vm_area* allocated_vma   = kmem_cache_alloc(vma_cache);
    struct vm_area* allocated_guard = is_stack ? kmem_cache_alloc(vma_cache) : nullptr;
    if (unlikely(!allocated_vma || (is_stack && !allocated_guard))) {
        vmm_free_pending_vmas(allocated_vma, allocated_guard);
        release_write(&space->lock);
        return nullptr;
    }

    memset(allocated_vma, 0, sizeof(struct vm_area));
    if (allocated_guard) memset(allocated_guard, 0, sizeof(struct vm_area));

    bool found = false;
    if (hint_addr) {
        struct rb_node* node = space->rb_root.rb_node;
        bool collision       = false;

        while (node) {
            struct vm_area* curr = rb_entry(node, struct vm_area, rb_node);
            if (addr < curr->end && curr->start < (addr + actual_size)) {
                collision = true;
                break;
            }

            node = (addr < curr->start) ? node->rb_left : node->rb_right;
        }

        if (collision) {
            if (is_fixed) {
                vmm_free_pending_vmas(allocated_vma, allocated_guard);
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
                final_shift = PAGE_SHIFT_SMALL;
                found       = vmm_find_gap_top_down(space, actual_size, PAGE_SIZE_SMALL, &addr);
            }
        } else {
            found = vmm_find_gap_bottom_up(space, actual_size, align, &addr);
            if (!found && align > PAGE_SIZE_SMALL) {
                final_shift = PAGE_SHIFT_SMALL;
                found       = vmm_find_gap_bottom_up(space, actual_size, PAGE_SIZE_SMALL, &addr);
            }
        }
    }

    if (unlikely(!found)) {
        KLOG_WARN("VMM: Out of virtual memory for space");
        vmm_free_pending_vmas(allocated_vma, allocated_guard);
        release_write(&space->lock);
        return nullptr;
    }

    uintptr_t map_start        = is_stack ? addr + PAGE_SIZE_SMALL : addr;
    uint32_t map_flags         = is_stack ? (flags & ~VMM_FLAG_GUARD) : flags;
    struct vm_area* target_vma = is_stack ? allocated_guard : allocated_vma;

    target_vma->start      = map_start;
    target_vma->end        = map_start + size;
    target_vma->page_shift = final_shift;
    target_vma->flags      = map_flags;
    target_vma->cache      = cache;

    target_vma->object        = vmo;
    target_vma->object_offset = vmo_offset;
    if (likely(vmo)) vm_object_ref(vmo);

    if (unlikely(!vmm_populate_vma_range(space, target_vma, map_start, size))) {
        if (vmo) vm_object_deref(vmo);
        vmm_free_pending_vmas(allocated_vma, allocated_guard);
        release_write(&space->lock);
        return nullptr;
    }

    if (!is_stack && vmm_try_merge(
                         space,
                         addr,
                         actual_size,
                         flags,
                         cache,
                         final_shift,
                         target_vma->object,
                         target_vma->object_offset
                     )) {
        if (vmo) vm_object_deref(vmo);
        kmem_cache_free(vma_cache, allocated_vma);
        release_write(&space->lock);
        return (void*)addr;
    }

    if (is_stack) {
        allocated_vma->start      = addr;
        allocated_vma->end        = addr + PAGE_SIZE_SMALL;
        allocated_vma->page_shift = PAGE_SHIFT_SMALL;
        allocated_vma->flags      = VMM_FLAG_GUARD;
        allocated_vma->cache      = CACHE_WRITE_BACK;
        allocated_vma->object     = nullptr;

        vmm_insert_vma(space, allocated_vma);
        vmm_insert_vma(space, allocated_guard);
        atomic_store_explicit(&space->cached_vma, allocated_guard, memory_order_relaxed);

        release_write(&space->lock);
        return (void*)allocated_guard->start;
    }

    vmm_insert_vma(space, allocated_vma);
    space->allocation_hint = allocated_vma->end;
    atomic_store_explicit(&space->cached_vma, allocated_vma, memory_order_relaxed);

    release_write(&space->lock);
    return (void*)addr;
}

void vmfree(struct vm_space* space, void* ptr, size_t size) {
    if (unlikely(size == 0)) return;

    uintptr_t start = (uintptr_t)ptr;
    uintptr_t end   = start + size;

    acquire_write(&space->lock);

    while (start < end) {
        struct vm_area* vma = vmm_find_vma_unsafe(space, start);
        if (!vma) {
            struct vm_area* next = vmm_find_next_vma_after_unsafe(space, start);

            if (!next || next->start >= end) break;
            vma = next;
        }

        uintptr_t unmap_start = max(start, vma->start);
        uintptr_t unmap_end   = min(end, vma->end);
        size_t unmap_size     = unmap_end - unmap_start;

        vmm_unmap_hardware_range(space, unmap_start, unmap_size, vma->page_shift);
        if (unmap_start == vma->start && unmap_end == vma->end) {
            // Case 1: Full VMA Removal
            vmm_remove_stack_guard_if_present(space, vma);

            rb_erase_augmented(&vma->rb_node, &space->rb_root, vma_compute_subtree_gap);
            if (vma->object) vm_object_deref(vma->object);
            kmem_cache_free(vma_cache, vma);
        } else if (unmap_start == vma->start) {
            // Case 2: Head Cut
            rb_erase_augmented(&vma->rb_node, &space->rb_root, vma_compute_subtree_gap);
            if (vma->object) vma->object_offset += (unmap_end - vma->start);
            vma->start = unmap_end;
            vmm_insert_vma(space, vma);
        } else if (unmap_end == vma->end) {
            // Case 3: Tail Cut
            vma->end = unmap_start;

            struct rb_node* next = rb_next(&vma->rb_node);
            if (next) {
                struct vm_area* next_vma = rb_entry(next, struct vm_area, rb_node);
                next_vma->own_gap        = next_vma->start - vma->end;
                vma_propagate_gap_up(&next_vma->rb_node);
            }

            vma_propagate_gap_up(&vma->rb_node);
        } else {
            // Case 4: Middle Punch (Split)
            struct vm_area* right_half = vmm_split_vma(space, vma, unmap_end);
            if (likely(right_half)) {
                vma->end = unmap_start;

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

void vmm_destroy_space(struct vm_space* space) {
    if (unlikely(!space)) return;
    acquire_write(&space->lock);

    struct rb_node* node = rb_first(&space->rb_root);
    while (node) {
        struct vm_area* vma  = rb_entry(node, struct vm_area, rb_node);
        struct rb_node* next = rb_next(node);

        vmm_unmap_hardware_range(space, vma->start, vma_size(vma), vma->page_shift);
        rb_erase_augmented(&vma->rb_node, &space->rb_root, vma_compute_subtree_gap);

        if (vma->object) vm_object_deref(vma->object);
        kmem_cache_free(vma_cache, vma);
        node = next;
    }

    atomic_store_explicit(&space->cached_vma, nullptr, memory_order_relaxed);
    space->rb_root = RB_ROOT;
    release_write(&space->lock);
}

bool vmm_clone_space(struct vm_space* parent, struct vm_space* child) {
    if (unlikely(!parent || !child || !parent->map || !child->map)) return false;

    acquire_read(&parent->lock);
    acquire_write(&child->lock);

    if (unlikely(!pagemap_clone(child->map, parent->map))) goto clone_fail;

    struct rb_node* node = rb_first(&parent->rb_root);
    while (node) {
        struct vm_area* parent_vma = rb_entry(node, struct vm_area, rb_node);
        struct vm_area* child_vma  = kmem_cache_alloc(vma_cache);
        if (!child_vma) goto clone_fail;

        memset(child_vma, 0, sizeof(struct vm_area));
        child_vma->start      = parent_vma->start;
        child_vma->end        = parent_vma->end;
        child_vma->page_shift = parent_vma->page_shift;
        child_vma->cache      = parent_vma->cache;
        child_vma->flags      = parent_vma->flags;

        if (!(parent_vma->flags & VMM_FLAG_SHARED) && (parent_vma->flags & VMM_FLAG_WRITE)) {
            parent_vma->flags |= VMM_FLAG_COW;
            child_vma->flags |= VMM_FLAG_COW;

            child_vma->object =
                vm_object_create_shadow(parent_vma->object, 0, parent_vma->object->size);
            child_vma->object_offset = parent_vma->object_offset;

            if (unlikely(!child_vma->object)) goto clone_fail;

            uint32_t pte_flags               = parent_vma->flags & ~VMM_FLAG_WRITE;
            pagemap_protect_args_t prot_args = {.flags = pte_flags, .cache = parent_vma->cache};

            for (uintptr_t addr = parent_vma->start; addr < parent_vma->end;
                 addr += vma_page_size(parent_vma)) {
                if (pagemap_translate(parent->map, addr)) {
                    prot_args.virt_addr = (void*)addr;
                    pagemap_protect(parent->map, &prot_args);
                }
            }
        } else {
            child_vma->object        = parent_vma->object;
            child_vma->object_offset = parent_vma->object_offset;
            vm_object_ref(child_vma->object);
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

int vmprotect(struct vm_space* space, uintptr_t ptr_addr, size_t size, uint32_t new_prots) {
    uintptr_t start = ptr_addr;
    uintptr_t end   = start + align_up(size, PAGE_SIZE_SMALL);

    acquire_write(&space->lock);
    while (start < end) {
        struct vm_area* vma = vmm_find_vma_unsafe(space, start);

        // Skip unmapped gaps
        if (!vma) {
            struct vm_area* next = vmm_find_next_vma_after_unsafe(space, start);

            if (!next || next->start >= end) break;
            vma = next;
        }

        uintptr_t prot_start = max(start, vma->start);
        uintptr_t prot_end   = min(end, vma->end);

        // Keep structural flags intact.
        const uint32_t structural_mask = ~(VMM_FLAG_READ | VMM_FLAG_WRITE | VMM_FLAG_EXECUTE);
        uint32_t updated_flags         = (vma->flags & structural_mask) | new_prots;

        // If the flags aren't changing, skip this VMA
        if (vma->flags == updated_flags) {
            start = prot_end;
            continue;
        }

        struct vm_area* target_vma = vma;

        if (prot_start > vma->start && prot_end < vma->end) {
            // Case 1: Middle Punch (Creates 3 VMAs)

            // Splits Left/Right
            target_vma = vmm_split_vma(space, vma, prot_start);
            if (!target_vma) goto fail;

            // Splits Right into Middle/Tail
            if (!vmm_split_vma(space, target_vma, prot_end)) goto fail;
        } else if (prot_start > vma->start) {
            // Case 2: Head Cut (Creates 2 VMAs, target is the right one)
            target_vma = vmm_split_vma(space, vma, prot_start);
            if (!target_vma) goto fail;
        } else if (prot_end < vma->end) {
            // Case 3: Tail Cut (Creates 2 VMAs, target is the left one)
            if (!vmm_split_vma(space, vma, prot_end)) goto fail;
            target_vma = vma;
        }

        target_vma->flags = updated_flags;

        pagemap_protect_args_t prot_args = {.flags = updated_flags, .cache = target_vma->cache};

        size_t page_size = 1ul << target_vma->page_shift;
        for (uintptr_t addr = prot_start; addr < prot_end; addr += page_size) {
            if (pagemap_translate(space->map, addr)) {
                prot_args.virt_addr = (void*)addr;
                pagemap_protect(space->map, &prot_args);
            }
        }

        // Attempt to merge the VMA with neighbors if protections now match
        vmm_try_merge(
            space,
            target_vma->start,
            vma_size(target_vma),
            target_vma->flags,
            target_vma->cache,
            target_vma->page_shift,
            target_vma->object,
            target_vma->object_offset
        );

        start = prot_end;
    }

    release_write(&space->lock);
    return ERR_OK;

fail:
    release_write(&space->lock);
    KLOG_ERROR("VMM: Out of memory while splitting VMAs for protection change.");
    return ERR_NO_MEM;
}