#ifndef KERNEL_ARCH_MEMORY_ARCH_MMU_H
#define KERNEL_ARCH_MEMORY_ARCH_MMU_H 1

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "memory/cache.h"

#define X86_MAX_PCID  4095
#define X86_MAX_PKEYS 15

// PKRU rights bits per key as defined by x86-64.
#define X86_PKEY_FLAG_NONE           0x0u
#define X86_PKEY_FLAG_ACCESS_DISABLE 0x1u
#define X86_PKEY_FLAG_WRITE_DISABLE  0x2u
#define X86_PKEY_FLAG_MASK           (X86_PKEY_FLAG_ACCESS_DISABLE | X86_PKEY_FLAG_WRITE_DISABLE)

#define USER_SPACE_END_4L     0x00007ffffffffffful
#define USER_SPACE_END_5L     0x00fffffffffffffful
#define KERNEL_SPACE_START_4L 0xffff800000000000ul
#define KERNEL_SPACE_START_5L 0xff00000000000000ul
#define KERNEL_SPACE_END      0xfffffffffffff000ul

typedef struct arch_pagemap arch_pagemap_t;

typedef struct {
    uintptr_t virt_addr;
    uintptr_t phys_addr;
    size_t length;

    uint32_t flags;
    cache_type_t cache;
    uint8_t pkey;
    size_t page_size;

    bool skip_tlb_flush;
} arch_mmu_map_args_t;

typedef struct {
    uintptr_t virt_addr;
    size_t length;
    bool free_phys;
    bool skip_tlb_flush;
} arch_mmu_unmap_args_t;

typedef struct {
    uintptr_t virt_addr;
    size_t length;

    uint32_t flags;
    cache_type_t cache;
    uint8_t pkey;

    bool skip_tlb_flush;
} arch_mmu_protect_args_t;

void arch_mmu_init(void);

arch_pagemap_t* arch_mmu_new_pagemap(void);
void arch_mmu_delete_pagemap(arch_pagemap_t* map);

int arch_mmu_allocate_pcid(arch_pagemap_t* map);
void arch_mmu_free_pcid(arch_pagemap_t* map);
int arch_mmu_allocate_pkey(arch_pagemap_t* map, uint32_t flags);
void arch_mmu_write_pkru(arch_pagemap_t* map);
void arch_mmu_free_pkey(arch_pagemap_t* map, uint8_t pkey);

int arch_mmu_map(arch_pagemap_t* map, const arch_mmu_map_args_t* args);
int arch_mmu_unmap(arch_pagemap_t* map, const arch_mmu_unmap_args_t* args);
int arch_mmu_remap(arch_pagemap_t* map, uintptr_t old_virt, uintptr_t new_virt, size_t length);
int arch_mmu_protect(arch_pagemap_t* map, const arch_mmu_protect_args_t* args);
uintptr_t
arch_mmu_translate(arch_pagemap_t* map, uintptr_t virt, uint32_t* out_flags, size_t* page_size);

void arch_mmu_load(arch_pagemap_t* map);
void arch_mmu_flush_tlb(arch_pagemap_t* map, uintptr_t virt, size_t length);
void arch_mmu_flush_local(arch_pagemap_t* map, uintptr_t virt, size_t length, uint32_t cpu_id);

int arch_mmu_shatter(arch_pagemap_t* map, uintptr_t virt);
int arch_mmu_collapse(arch_pagemap_t* map, uintptr_t virt);
bool arch_mmu_test_and_clear_dirty(arch_pagemap_t* map, uintptr_t virt);
bool arch_mmu_test_and_clear_accessed(arch_pagemap_t* map, uintptr_t virt);
int arch_mmu_clone(arch_pagemap_t* dest, arch_pagemap_t* src);
void arch_mmu_sync_kernel(arch_pagemap_t* target_map);

#endif