#include "memory/pagemap.h"

#include <errno.h>

#include "libs/log.h"
#include "libs/spinlock.h"
#include "memory/arch_mmu.h"

void pagemap_create(pagemap_t* map) {
    if (!map) {
        return;
    }

    create_interrupt_lock(&map->lock);

    arch_mmu_create(&map->arch);
}

void pagemap_release(pagemap_t* map) {
    if (!map) {
        return;
    }

    acquire_interrupt_lock(&map->lock);
    arch_mmu_destroy(&map->arch);
    release_interrupt_lock(&map->lock);
}

void pagemap_load(pagemap_t* map) {
    if (!map) {
        return;
    }

    arch_mmu_allocate_pcid(&map->arch);
    arch_mmu_load(&map->arch);
    arch_mmu_write_pkru(&map->arch);
}

int pagemap_allocate_pkey(pagemap_t* map) {
    if (!map) {
        return -EINVAL;
    }

    return arch_mmu_allocate_pkey(&map->arch);
}

void pagemap_free_pkey(pagemap_t* map, uint8_t pkey) {
    if (!map) {
        return;
    }

    arch_mmu_free_pkey(&map->arch, pkey);
}

bool pagemap_map(pagemap_t* map, pagemap_map_args_t* args) {
    if (!map || !args) return false;

    int status = arch_mmu_map(
        &map->arch,
        (uintptr_t)args->virt_addr,
        (uintptr_t)args->phys_addr,
        args->length,
        args->flags,
        args->cache,
        args->pkey,
        args->page_size
    );

    if (status != 0) {
        KLOG_DEBUG("status = %d\n", status);
    }

    return (status == 0);
}

void pagemap_unmap(pagemap_t* map, pagemap_unmap_args_t* args) {
    if (!map || !args) {
        return;
    }

    arch_mmu_unmap(&map->arch, (uintptr_t)args->virt_addr, args->length, args->free_phys);
}

void pagemap_protect(pagemap_t* map, pagemap_protect_args_t* args) {
    if (!map || !args) {
        return;
    }

    arch_mmu_protect(
        &map->arch,
        (uintptr_t)args->virt_addr,
        args->length,
        args->flags,
        args->cache,
        args->pkey
    );
}

uintptr_t pagemap_translate(pagemap_t* map, uintptr_t virt_addr) {
    if (!map) {
        return 0;
    }

    return arch_mmu_translate(&map->arch, virt_addr, nullptr);
}

size_t pagemap_get_flags(pagemap_t* map, uintptr_t virt_addr) {
    if (!map) return 0;

    uint32_t generic_flags = 0;
    arch_mmu_translate(&map->arch, virt_addr, &generic_flags);
    return generic_flags;
}