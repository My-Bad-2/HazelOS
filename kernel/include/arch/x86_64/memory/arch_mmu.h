#ifndef KERNEL_ARCH_MEMORY_ARCH_MMU_H
#define KERNEL_ARCH_MEMORY_ARCH_MMU_H 1

#include <stddef.h>
#include <stdint.h>

#include "libs/spinlock.h"

#define X86_MAX_PCID  4095
#define X86_MAX_PKEYS 15

#define USER_SPACE_END_4L 0x00007ffffffffffful
#define USER_SPACE_END_5L 0x00fffffffffffffful

typedef struct {
    spinlock_t pcid_lock;
    uint64_t pcid_bitmap[64];  // 64 * 64 = 4096 entries
} cpu_local_mmu_t;

typedef struct {
    uintptr_t phys_root;
    uint16_t* pcids;
    uint32_t pcids_capacity;
    uint16_t active_pkeys;
    spinlock_t lock;
} arch_pagemap_t;

static inline bool arch_is_canonical(uintptr_t addr, int max_levels) {
    if (max_levels == 5) {
        // LA57 (5-level canonical check)
        uintptr_t top = addr >> 56;
        return (top == 0 || top == 0xff);
    } else {
        uintptr_t top = addr >> 47;
        return (top == 0 || top == 0x1ffff);
    }
}

void arch_mmu_init(void);

int arch_mmu_allocate_pcid(arch_pagemap_t* map);
void arch_mmu_free_pcid(arch_pagemap_t* map);
int arch_mmu_allocate_pkey(arch_pagemap_t* map);
void arch_mmu_write_pkru(arch_pagemap_t* map);
void arch_mmu_free_pkey(arch_pagemap_t* map, uint8_t pkey);

int arch_mmu_create(arch_pagemap_t* map);
void arch_mmu_destroy(arch_pagemap_t* map);

int arch_mmu_map(
    arch_pagemap_t* map,
    uintptr_t virt,
    uintptr_t phys,
    size_t length,
    uint32_t flags,
    uint32_t cache,
    uint8_t pkey,
    size_t page_size
);
int arch_mmu_unmap(arch_pagemap_t* map, uintptr_t virt, size_t length, bool free_phys);
int arch_mmu_remap(arch_pagemap_t* map, uintptr_t old_virt, uintptr_t new_virt, size_t length);
int arch_mmu_protect(
    arch_pagemap_t* map,
    uintptr_t virt,
    size_t length,
    uint32_t flags,
    uint32_t cache,
    uint8_t pkey
);
uintptr_t
arch_mmu_translate(arch_pagemap_t* map, uintptr_t virt, uint32_t* out_flags, size_t* page_size);

void arch_mmu_load(arch_pagemap_t* map);
void arch_mmu_flush_tlb(arch_pagemap_t* map, uintptr_t virt, size_t length);

int arch_mmu_shatter(arch_pagemap_t* map, uintptr_t virt);
int arch_mmu_collapse(arch_pagemap_t* map, uintptr_t virt);
bool arch_mmu_test_and_clear_dirty(arch_pagemap_t* map, uintptr_t virt);
bool arch_mmu_test_and_clear_accessed(arch_pagemap_t* map, uintptr_t virt);
int arch_mmu_clone(arch_pagemap_t* dest, arch_pagemap_t* src);
void arch_mmu_sync_kernel(arch_pagemap_t* target_map);

#endif