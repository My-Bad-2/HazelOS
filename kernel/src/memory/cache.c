#include <stdint.h>
#include <string.h>

#include "libs/dlist.h"
#include "libs/spinlock.h"
#include "libs/xarray.h"
#include "memory/heap.h"
#include "memory/memory.h"
#include "memory/pagemap.h"
#include "memory/vma.h"

#define PAGE_SIZE  PAGE_SIZE_SMALL
#define PAGE_SHIFT PAGE_SHIFT_SMALL

#define BATCH_SIZE     16
#define CPU_CACHE_SIZE 64

struct slab {
    struct dlist_head list;
    void* base;
    void* freelist;

    uint32_t in_use;
    uint32_t free_count;
    uint32_t color_offset;
};

struct kmem_cache_cpu {
    void** freelist;
    uint32_t count;
    uint32_t limit;
};

struct kmem_cache {
    const char* name;
    size_t obj_size;
    size_t size;
    size_t align;
    uint32_t flags;
    void (*ctor)(void*);

    xarray_t slab_map;
    struct kmem_cache_cpu** cpu_slab;

    spinlock_t node_lock;
    struct dlist_head partial;
    uint32_t color_max;
    uint32_t color_next;
};

static inline uintptr_t obj_to_index(void* addr) {
    return (uintptr_t)addr >> PAGE_SHIFT;
}

static inline void set_free_obj_next(void* obj, void* next) {
    *(void**)obj = next;
}

static inline void* get_free_obj_next(void* obj) {
    return *(void**)obj;
}

static void* alloc_pages(void) {
    void* p = vmalloc(
        &kernel_space,
        PAGE_SIZE,
        VMM_FLAG_WRITE | VMM_FLAG_READ,
        CACHE_WRITE_BACK,
        PAGE_SIZE
    );

    if (p) {
        memset(p, 0, PAGE_SIZE_SMALL);
    }

    return p;
}

static void free_pages(void* p) {
    vmfree(&kernel_space, p, PAGE_SIZE);
}
