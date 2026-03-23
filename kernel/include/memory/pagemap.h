#ifndef KERNEL_MEMORY_PAGEMAP_H
#define KERNEL_MEMORY_PAGEMAP_H 1

#include <stddef.h>
#include <stdint.h>

#include "libs/spinlock.h"
#include "memory/arch_mmu.h"

#ifdef __cplusplus
extern "C" {
#endif

#define VMM_FLAG_NONE            0x001u
#define VMM_FLAG_READ            0x002u
#define VMM_FLAG_WRITE           0x004u
#define VMM_FLAG_EXECUTE         0x008u
#define VMM_FLAG_USER            0x010u
#define VMM_FLAG_GLOBAL          0x020u
#define VMM_FLAG_SHARED          0x040u
#define VMM_FLAG_PRIVATE         0x080u
#define VMM_FLAG_DEMAND          0x100u
#define VMM_FLAG_STACK           0x200u
#define VMM_FLAG_MMIO            0x400u
#define VMM_FLAG_GUARD           0x800u
#define VMM_FLAG_FIXED           0x1000u
#define VMM_FLAG_LOCKED          0x2000u
#define VMM_FLAG_POPULATE        0x4000u
#define VMM_FLAG_FIXED_NOREPLACE 0x8000u

#define VMM_FLAG_COW VMM_FLAG_SHARED

typedef enum {
    CACHE_UNCACHEABLE = 0,
    CACHE_MMIO,
    CACHE_WRITE_THROUGH,
    CACHE_WRITE_PROTECTED,
    CACHE_WRITE_COMBINING,
    CACHE_WRITE_BACK,
    CACHE_DEVICE,
    CACHE_FRAMEBUFFER,
    CACHE_ROM,
} cache_type_t;

// Per Process
typedef struct {
    arch_pagemap_t arch;
    spinlock_t lock;
} pagemap_t;

typedef struct {
    void* virt_addr;
    void* phys_addr;
    size_t length;

    uint32_t flags;
    cache_type_t cache;
    uint32_t page_size;

    uint8_t pkey;
    bool skip_flush;
} pagemap_map_args_t;

typedef struct {
    void* virt_addr;
    size_t length;
    bool free_phys;
} pagemap_unmap_args_t;

typedef struct {
    void* virt_addr;
    uint32_t flags;
    size_t length;
    cache_type_t cache;
    uint8_t pkey;
} pagemap_protect_args_t;

int pagemap_allocate_pkey(pagemap_t* map);
void pagemap_free_pkey(pagemap_t* map, uint8_t pkey);

bool pagemap_map(pagemap_t* map, pagemap_map_args_t* args);
void pagemap_unmap(pagemap_t* map, pagemap_unmap_args_t* args);
void pagemap_protect(pagemap_t* map, pagemap_protect_args_t* args);
bool pagemap_shatter(pagemap_t* map, uintptr_t virt_addr);
bool pagemap_collapse(pagemap_t* map, uintptr_t virt_addr);

uintptr_t pagemap_translate(pagemap_t* map, uintptr_t virt_addr);
size_t pagemap_get_flags(pagemap_t* map, uintptr_t virt_addr);

bool pagemap_test_and_clear_dirty(pagemap_t* map, uintptr_t virt_addr);
bool pagemap_test_and_clear_accessed(pagemap_t* map, uintptr_t virt_addr);

void pagemap_create(pagemap_t* map);
void pagemap_load(pagemap_t* map);
void pagemap_release(pagemap_t* map);
void pagemap_sync_kernel(pagemap_t* target_map);
bool pagemap_clone(pagemap_t* dest, pagemap_t* src);

void pagemap_global_init();

#ifdef __cplusplus
}
#endif

#endif