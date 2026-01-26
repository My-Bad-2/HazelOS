#ifndef KERNEL_MEMORY_HEAP_H
#define KERNEL_MEMORY_HEAP_H 1

#include "libs/dlist.h"
#include "libs/spinlock.h"
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif



struct vma_slab {
    struct dlist_head list;
    void* vaddr;
    uint32_t in_use;
    uint32_t free_idx;
    void* freelist;
};

struct vma_kmem_cache {
    char name[32];
    uint32_t obj_size;
    uint32_t slab_size;
    uint32_t objs_per_slab;

    spinlock_t lock;
    struct dlist_head partial;
    struct dlist_head full;
};

struct vma_huge_cache {
    uint32_t obj_size;
    uint32_t slab_size;
    uint32_t objs_per_slab;
};

void* kmalloc(size_t size);
void kfree(void* ptr, size_t size);

void* aligned_kalloc(size_t alignment, size_t size);
void aligned_kfree(void* ptr, size_t size);

void kheap_init(void);

#ifdef __cplusplus
}
#endif

#endif