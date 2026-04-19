#include "memory/pagemap.h"

#include <stdint.h>
#include <string.h>

#include "core/errors.h"
#include "libs/spinlock.h"
#include "memory/arch_mmu.h"
#include "memory/heap.h"

static kmem_cache_t* pagemap_cache = nullptr;

pagemap_t* pagemap_create(void) {
    if (!pagemap_cache) {
        pagemap_cache =
            kmem_cache_create("pagemap_cache", sizeof(pagemap_t), _Alignof(pagemap_t), 0, nullptr);

        if (!pagemap_cache) {
            return nullptr;
        }
    }

    pagemap_t* map = kmem_cache_alloc(pagemap_cache);
    if (!map) {
        return nullptr;
    }

    memset(map, 0, sizeof(*map));

    create_spinlock(&map->lock);
    map->arch = arch_mmu_new_pagemap();

    if (!map->arch) {
        kmem_cache_free(pagemap_cache, map);
        return nullptr;
    }

    return map;
}

void pagemap_release(pagemap_t* map) {
    if (!map) {
        return;
    }

    size_t flags         = acquire_interrupt_lock(&map->lock);
    arch_pagemap_t* arch = map->arch;
    map->arch            = nullptr;
    release_interrupt_lock(&map->lock, flags);

    arch_mmu_delete_pagemap(arch);
    kmem_cache_free(pagemap_cache, map);
}

void pagemap_load(pagemap_t* map) {
    if (!map || !map->arch) {
        return;
    }

    arch_mmu_allocate_pcid(map->arch);
    arch_mmu_load(map->arch);
    arch_mmu_write_pkru(map->arch);
}

int pagemap_allocate_pkey(pagemap_t* map) {
    if (!map || !map->arch) {
        return ERR_INVALID;
    }

    return arch_mmu_allocate_pkey(map->arch);
}

void pagemap_free_pkey(pagemap_t* map, uint8_t pkey) {
    if (!map || !map->arch) {
        return;
    }

    arch_mmu_free_pkey(map->arch, pkey);
}

int pagemap_map_ex(pagemap_t* map, const pagemap_map_op_t* op) {
    if (!map || !map->arch || !op || op->length == 0) {
        return ERR_INVALID;
    }

    arch_mmu_map_args_t arch_args = {
        .virt_addr      = op->virt_addr,
        .phys_addr      = op->phys_addr,
        .length         = op->length,
        .flags          = op->flags,
        .cache          = op->cache,
        .pkey           = op->pkey,
        .page_size      = op->page_size,
        .skip_tlb_flush = op->skip_flush,
    };

    return arch_mmu_map(map->arch, &arch_args);
}

int pagemap_unmap_ex(pagemap_t* map, const pagemap_unmap_op_t* op) {
    if (!map || !map->arch || !op || op->length == 0) {
        return ERR_INVALID;
    }

    arch_mmu_unmap_args_t arch_args = {
        .virt_addr      = op->virt_addr,
        .length         = op->length,
        .free_phys      = op->free_phys,
        .skip_tlb_flush = op->skip_flush,
    };

    return arch_mmu_unmap(map->arch, &arch_args);
}

int pagemap_protect_ex(pagemap_t* map, const pagemap_protect_op_t* op) {
    if (!map || !map->arch || !op || op->length == 0) {
        return ERR_INVALID;
    }

    arch_mmu_protect_args_t arch_args = {
        .virt_addr      = op->virt_addr,
        .length         = op->length,
        .flags          = op->flags,
        .cache          = op->cache,
        .pkey           = op->pkey,
        .skip_tlb_flush = op->skip_flush,
    };

    return arch_mmu_protect(map->arch, &arch_args);
}

bool pagemap_lookup(pagemap_t* map, pagemap_lookup_t* query) {
    if (!map || !map->arch || !query) {
        return false;
    }

    query->flags     = 0;
    query->page_size = 0;
    query->phys_addr =
        arch_mmu_translate(map->arch, query->virt_addr, &query->flags, &query->page_size);
    query->present = (query->phys_addr != 0);

    return query->present;
}

bool pagemap_map(pagemap_t* map, pagemap_map_args_t* args) {
    if (!args) {
        return false;
    }

    const pagemap_map_op_t op = {
        .virt_addr  = (uintptr_t)args->virt_addr,
        .phys_addr  = (uintptr_t)args->phys_addr,
        .length     = args->length,
        .flags      = args->flags,
        .cache      = args->cache,
        .page_size  = args->page_size,
        .pkey       = args->pkey,
        .skip_flush = args->skip_flush,
    };

    return pagemap_map_ex(map, &op) == 0;
}

void pagemap_unmap(pagemap_t* map, pagemap_unmap_args_t* args) {
    if (!args) {
        return;
    }

    const pagemap_unmap_op_t op = {
        .virt_addr  = (uintptr_t)args->virt_addr,
        .length     = args->length,
        .free_phys  = args->free_phys,
        .skip_flush = false,
    };

    (void)pagemap_unmap_ex(map, &op);
}

void pagemap_protect(pagemap_t* map, pagemap_protect_args_t* args) {
    if (!args) {
        return;
    }

    const pagemap_protect_op_t op = {
        .virt_addr  = (uintptr_t)args->virt_addr,
        .flags      = args->flags,
        .length     = args->length,
        .cache      = args->cache,
        .pkey       = args->pkey,
        .skip_flush = false,
    };

    (void)pagemap_protect_ex(map, &op);
}

bool pagemap_resolve_vaddr(
    pagemap_t* map,
    uintptr_t virt_addr,
    uintptr_t* phys_addr,
    uint32_t* flags,
    size_t* page_size
) {
    if (!map || !map->arch) {
        return false;
    }

    uintptr_t phys = arch_mmu_translate(map->arch, virt_addr, flags, page_size);
    if (phys_addr) {
        *phys_addr = phys;
    }

    return (phys != 0);
}

uintptr_t pagemap_translate(pagemap_t* map, uintptr_t virt_addr) {
    if (!map || !map->arch) {
        return 0;
    }

    return arch_mmu_translate(map->arch, virt_addr, nullptr, nullptr);
}

size_t pagemap_get_flags(pagemap_t* map, uintptr_t virt_addr) {
    if (!map || !map->arch) {
        return 0;
    }

    uint32_t generic_flags = 0;
    arch_mmu_translate(map->arch, virt_addr, &generic_flags, nullptr);
    return generic_flags;
}

bool pagemap_shatter(pagemap_t* map, uintptr_t virt_addr) {
    if (!map || !map->arch) {
        return false;
    }

    return arch_mmu_shatter(map->arch, virt_addr) == 0;
}

bool pagemap_collapse(pagemap_t* map, uintptr_t virt_addr) {
    if (!map || !map->arch) {
        return false;
    }

    return arch_mmu_collapse(map->arch, virt_addr) == 0;
}

bool pagemap_test_and_clear_dirty(pagemap_t* map, uintptr_t virt_addr) {
    if (!map || !map->arch) {
        return false;
    }

    return arch_mmu_test_and_clear_dirty(map->arch, virt_addr);
}

bool pagemap_test_and_clear_accessed(pagemap_t* map, uintptr_t virt_addr) {
    if (!map || !map->arch) {
        return false;
    }

    return arch_mmu_test_and_clear_accessed(map->arch, virt_addr);
}

void pagemap_sync_kernel(pagemap_t* target_map) {
    if (!target_map || !target_map->arch) {
        return;
    }

    arch_mmu_sync_kernel(target_map->arch);
}

bool pagemap_clone(pagemap_t* dest, pagemap_t* src) {
    if (!dest || !src || !src->arch || dest == src) {
        return false;
    }

    arch_pagemap_t* new_arch = arch_mmu_new_pagemap();
    if (!new_arch) {
        return false;
    }

    pagemap_t* first  = ((uintptr_t)dest < (uintptr_t)src) ? dest : src;
    pagemap_t* second = (first == dest) ? src : dest;

    size_t first_flags  = acquire_interrupt_lock(&first->lock);
    size_t second_flags = acquire_interrupt_lock(&second->lock);

    arch_pagemap_t* src_arch = src->arch;
    int status               = src_arch ? arch_mmu_clone(new_arch, src_arch) : ERR_INVALID;
    arch_pagemap_t* old_arch = nullptr;

    if (status == 0) {
        old_arch   = dest->arch;
        dest->arch = new_arch;
    }

    release_interrupt_lock(&second->lock, second_flags);
    release_interrupt_lock(&first->lock, first_flags);

    if (status != 0) {
        arch_mmu_delete_pagemap(new_arch);
        return false;
    }

    arch_mmu_delete_pagemap(old_arch);

    return true;
}
