#ifndef KERNEL_MEMORY_HEAP_H
#define KERNEL_MEMORY_HEAP_H 1

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SLAB_NO_OFFSLAB 0x8000
#define SLAB_DEBUG_FREE 0x0100  // Poison memory on free
#define SLAB_RED_ZONES  0x0200  // Add redzones
#define SLAB_PANIC      0x0800  // Panic on allocation failure

typedef struct kmem_cache kmem_cache_t;

void kheap_init(void);

kmem_cache_t*
kmem_cache_create(const char* name, size_t size, size_t align, size_t flags, void (*ctor)(void*));
void* kmem_cache_alloc(kmem_cache_t* cache);

void kmem_cache_free(kmem_cache_t* cache, void* ptr);
void kmem_cache_destroy(kmem_cache_t* cache);

void* kmalloc(size_t size);
void kfree(void* ptr);

#ifdef __cplusplus
}
#endif

#endif