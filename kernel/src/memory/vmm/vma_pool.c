#include "../internal/vma_pool.h"

#include <string.h>

#include "libs/log.h"
#include "libs/spinlock.h"
#include "memory/memory.h"
#include "memory/pmm.h"
#include "memory/vma.h"

#include "../internal/vma_tree.h"

#define VMA_SLAB_SIZE PAGE_SIZE_SMALL
#define VMAS_PER_SLAB (VMA_SLAB_SIZE / sizeof(vm_area_t))

void vma_pool_init(vm_space_t* space) {
    create_spinlock(&space->pool_lock);
    space->free_vma_pool = nullptr;
}

static bool vma_expand_pool(vm_space_t* space) {
    vm_space_t* kspace = kernel_space;

    bool needs_lock = (space != kspace);
    void* phys      = pmm_alloc(1);

    if (!phys) {
        return false;
    }

    if (needs_lock) {
        acquire_write(&kspace->lock);
    }

    uintptr_t addr;
    if (!vmm_find_gap_bottom_up(kspace, VMA_SLAB_SIZE, PAGE_SIZE_SMALL, &addr)) {
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

    vmm_insert_vma(kspace, meta_vma);

    if (needs_lock) {
        release_write(&kspace->lock);
    }

    for (int i = 1; i < VMAS_PER_SLAB - 1; ++i) {
        *(vm_area_t**)&new_slab[i] = &new_slab[i + 1];
    }

    *(vm_area_t**)(&new_slab[VMAS_PER_SLAB - 1]) = space->free_vma_pool;
    space->free_vma_pool                         = &new_slab[1];

    return true;
}

vm_area_t* vma_new(vm_space_t* space) {
    acquire_spinlock(&space->pool_lock);

    if (!space->free_vma_pool) {
        if (!vma_expand_pool(space)) {
            release_spinlock(&space->pool_lock);
            return nullptr;
        }
    }

    vm_area_t* vma       = space->free_vma_pool;
    space->free_vma_pool = *(vm_area_t**)vma;

    release_spinlock(&space->pool_lock);

    memset(vma, 0, sizeof(vm_area_t));
    return vma;
}

void vma_free_struct(vm_space_t* space, vm_area_t* vma) {
    acquire_spinlock(&space->pool_lock);

    *(vm_area_t**)vma    = space->free_vma_pool;
    space->free_vma_pool = vma;

    release_spinlock(&space->pool_lock);
}