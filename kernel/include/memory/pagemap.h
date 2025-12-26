#ifndef KERNEL_MEMORY_VMM_H
#define KERNEL_MEMORY_VMM_H 1

#include <stddef.h>
#include <stdint.h>

#include "libs/spinlock.h"

#define VMM_FLAG_NONE    0x01
#define VMM_FLAG_READ    0x02
#define VMM_FLAG_WRITE   0x04
#define VMM_FLAG_EXECUTE 0x08
#define VMM_FLAG_USER    0x10
#define VMM_FLAG_GLOBAL  0x20

typedef enum {
    CACHE_UNCACHEABLE = 0,
    CACHE_MMIO,
    CACHE_WRITE_THROUGH,
    CACHE_WRITE_PROTECTED,
    CACHE_WRITE_COMBINING,
    CACHE_WRITE_BACK,
    CACHE_DEVICE,
} cache_type_t;

// Per Process
typedef struct {
    uintptr_t phys_root;
    interrupt_lock_t lock;
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
    cache_type_t cache;
} pagemap_protect_args_t;

bool pagemap_map(pagemap_t* map, pagemap_map_args_t args);
void pagemap_unmap(pagemap_t* map, pagemap_unmap_args_t args);
void pagemap_protect(pagemap_t* map, pagemap_protect_args_t args);
bool pagemap_shatter(pagemap_t* map, uintptr_t virt_addr);

uintptr_t pagemap_translate(pagemap_t* map, uintptr_t virt_addr);

#endif