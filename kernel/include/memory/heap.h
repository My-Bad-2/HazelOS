#ifndef KERNEL_MEMORY_HEAP_H
#define KERNEL_MEMORY_HEAP_H 1

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SLAB_HWCACHE_ALIGN 0x1
#define SLAB_PANIC         0x2

typedef struct kmem_cache kmem_cache_t;

kmem_cache_t*
kmem_cache_create(const char* name, size_t size, size_t align, uint32_t flags, void (*ctor)(void*));
void* kmem_cache_alloc(kmem_cache_t* cache, int flags);
void kmem_cache_free(kmem_cache_t* cache, void* ptr);
void kmem_cache_destroy(kmem_cache_t* cache);
int kmem_cache_shrink(kmem_cache_t* cache);

void* kmalloc(size_t size);
void kfree(void* ptr, size_t size);

void* aligned_kalloc(size_t alignment, size_t size);
void aligned_kfree(void* ptr, size_t size);

void kheap_init(void);

#ifdef __cplusplus
}
#endif

#endif