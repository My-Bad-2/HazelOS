#include "memory/pagemap.h"

#include <errno.h>
#include <stdint.h>
#include <string.h>

#include "core/errors.h"
#include "libs/spinlock.h"
#include "memory/arch_mmu.h"
#include "memory/heap.h"
#include "memory/memory.h"
#include "memory/vmm.h"

static kmem_cache_t* pagemap_cache = nullptr;

pagemap_t* pagemap_create(void) {
    if (!pagemap_cache) {
        pagemap_cache =
            kmem_cache_create("pagemap_cache", sizeof(pagemap_t), _Alignof(pagemap_t), 0, nullptr);
    }

    pagemap_t* map = kmem_cache_alloc(pagemap_cache);

    create_spinlock(&map->lock);
    arch_mmu_create(&map->arch);

    return map;
}

void pagemap_release(pagemap_t* map) {
    if (!map) {
        return;
    }

    size_t flags = acquire_interrupt_lock(&map->lock);
    arch_mmu_destroy(&map->arch);
    release_interrupt_lock(&map->lock, flags);
    kmem_cache_free(pagemap_cache, map);
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
    if (!map || !args) {
        return false;
    }

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

bool pagemap_resolve_vaddr(
    pagemap_t* map,
    uintptr_t virt_addr,
    uintptr_t* phys_addr,
    uint32_t* flags,
    size_t* page_size
) {
    if (!map) {
        return false;
    }

    uintptr_t phys = arch_mmu_translate(&map->arch, virt_addr, flags, page_size);
    if (phys_addr) {
        *phys_addr = phys;
    }

    return (phys != 0);
}

uintptr_t pagemap_translate(pagemap_t* map, uintptr_t virt_addr) {
    if (!map) {
        return 0;
    }

    return arch_mmu_translate(&map->arch, virt_addr, nullptr, nullptr);
}

size_t pagemap_get_flags(pagemap_t* map, uintptr_t virt_addr) {
    if (!map) {
        return 0;
    }

    uint32_t generic_flags = 0;
    arch_mmu_translate(&map->arch, virt_addr, &generic_flags, nullptr);
    return generic_flags;
}

bool pagemap_shatter(pagemap_t* map, uintptr_t virt_addr) {
    if (!map) {
        return false;
    }

    return arch_mmu_shatter(&map->arch, virt_addr) == 0;
}

bool pagemap_collapse(pagemap_t* map, uintptr_t virt_addr) {
    if (!map) {
        return false;
    }

    return arch_mmu_collapse(&map->arch, virt_addr) == 0;
}

bool pagemap_test_and_clear_dirty(pagemap_t* map, uintptr_t virt_addr) {
    if (!map) {
        return false;
    }

    return arch_mmu_test_and_clear_dirty(&map->arch, virt_addr);
}

bool pagemap_test_and_clear_accessed(pagemap_t* map, uintptr_t virt_addr) {
    if (!map) {
        return false;
    }

    return arch_mmu_test_and_clear_accessed(&map->arch, virt_addr);
}

void pagemap_sync_kernel(pagemap_t* target_map) {
    if (!target_map) {
        return;
    }

    arch_mmu_sync_kernel(&target_map->arch);
}

bool pagemap_clone(pagemap_t* dest, pagemap_t* src) {
    if (!dest || !src) {
        return false;
    }

    if (arch_mmu_create(&dest->arch) != 0) {
        return false;
    }

    create_spinlock(&dest->lock);

    size_t flags_src  = acquire_interrupt_lock(&src->lock);
    size_t flags_dest = acquire_interrupt_lock(&dest->lock);

    int status = arch_mmu_clone(&dest->arch, &src->arch);

    release_interrupt_lock(&dest->lock, flags_dest);
    release_interrupt_lock(&src->lock, flags_src);

    if (status != 0) {
        arch_mmu_destroy(&dest->arch);
        return false;
    }

    return true;
}

int copy_between_spaces(
    struct process* dest_proc,
    void* dest_addr,
    struct process* src_proc,
    const void* src_addr,
    size_t len
) {
    if (len == 0) {
        return ERR_OK;
    }

    if (!dest_addr || !src_addr) {
        return ERR_FAULT;
    }

    size_t copied = 0;

    while (copied < len) {
        uintptr_t current_src_vaddr = (uintptr_t)src_addr + copied;
        uintptr_t current_dst_vaddr = (uintptr_t)dest_addr + copied;

        uintptr_t src_paddr, dst_paddr;
        uint32_t src_flags, dst_flags;
        size_t src_page_size, dst_page_size;

        if (!pagemap_resolve_vaddr(
                src_proc->map,
                current_src_vaddr,
                &src_paddr,
                &src_flags,
                &src_page_size
            )) {
            return ERR_FAULT;
        }

        if (!pagemap_resolve_vaddr(
                dest_proc->map,
                current_dst_vaddr,
                &dst_paddr,
                &dst_flags,
                &dst_page_size
            )) {
            return ERR_FAULT;
        }

        if (!(dst_flags & VMM_FLAG_WRITE) || !(dst_flags & VMM_FLAG_USER)) {
            return ERR_DENIED;
        }

        size_t src_offset = current_src_vaddr & (src_page_size - 1);
        size_t dst_offset = current_dst_vaddr & (dst_page_size - 1);

        size_t src_remaining = src_page_size - src_offset;
        size_t dst_remaining = dst_page_size - dst_offset;

        size_t chunk = (src_remaining < dst_remaining) ? src_remaining : dst_remaining;
        chunk        = chunk < (len - copied) ? chunk : len - copied;

        void* k_src  = (void*)to_higher_half((uintptr_t)src_paddr);
        void* k_dest = (void*)to_higher_half((uintptr_t)dst_paddr);

        memcpy(k_dest, k_src, chunk);
        copied += chunk;
    }

    return ERR_OK;
}