#ifndef KERNEL_MEMORY_HEAP_H
#define KERNEL_MEMORY_HEAP_H 1

#include <stddef.h>

#include "sched/rcu.h"

#ifdef __cplusplus
extern "C" {
#endif

#define SLAB_TYPESAFE_BY_RCU 0x1000
#define SLAB_HWCACHE_ALIGN   0x2000
#define SLAB_NEVER_MERGE     0x4000
#define SLAB_NO_OFFSLAB      0x8000

#if KERNEL_DEBUG
#define SLAB_DEBUG_FREE 0x0100  // Poison memory on free
#define SLAB_RED_ZONES  0x0200  // Add redzones
#define SLAB_PANIC      0x0800  // Panic on allocation failure
#else
#define SLAB_DEBUG_FREE 0  // Poison memory on free
#define SLAB_RED_ZONES  0  // Add redzones
#define SLAB_PANIC      0  // Panic on allocation failure
#endif

typedef struct kmem_cache kmem_cache_t;

void kheap_init(void);

kmem_cache_t*
kmem_cache_create(const char* name, size_t size, size_t align, size_t flags, void (*ctor)(void*));
void kmem_cache_destroy(kmem_cache_t* cache);
size_t kmem_cache_shrink(kmem_cache_t* cache);

void* kmem_cache_alloc(kmem_cache_t* cache);
void kmem_cache_free(kmem_cache_t* cache, void* ptr);

void* kmalloc(size_t size);
void kfree(void* ptr);

static inline void __kfree_rcu_handler(struct rcu_head* head) {
    size_t offset = (size_t)head->func;

    void* obj = (char*)head - offset;
    kfree(obj);
}

#define kfree_rcu(ptr, rcu_field)                                     \
    do {                                                              \
        typeof(ptr) __ptr     = (ptr);                                \
        size_t __offset       = offsetof(typeof(*__ptr), rcu_field);  \
        __ptr->rcu_field.func = (void (*)(struct rcu_head*))__offset; \
        call_rcu(&__ptr->rcu_field, __kfree_rcu_handler);             \
    } while (0)

#ifdef __cplusplus
}
#endif

#endif