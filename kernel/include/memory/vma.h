#ifndef KERNEL_MEMORY_VMA_H
#define KERNEL_MEMORY_VMA_H 1

#include "libs/rb_tree.h"
#include "libs/spinlock.h"
#include "memory/pagemap.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct vm_area {
    struct rb_node rb_node;

    size_t subtree_max_gap;  // Max gap in this subtree
    size_t own_gap;          // Gap between prev->end and this->start

    uintptr_t start;
    uintptr_t end;  // Exclusive: [Start, end)
    size_t size;
    size_t page_size;  // Actual page size used (4K, 2M or 1G)

    uint32_t flags;
    cache_type_t cache;
} vm_area_t;

typedef struct [[gnu::aligned(CACHE_LINE_SIZE)]] {
    struct rb_root rb_root;
    pagemap_t* map;

    _Atomic(vm_area_t*) cached_vma;
    rwlock_t lock;

    uintptr_t start_limit;
    uintptr_t end_limit;
    uintptr_t allocation_hint;

    vm_area_t* free_vma_pool;
} vm_space_t;

void vmm_init_global(void);
void vmm_init_space(vm_space_t* space, pagemap_t* map, uintptr_t start, uintptr_t end);

void* vmalloc(vm_space_t* space, size_t size, uint32_t flags, cache_type_t cache, size_t alignment);

void* vmalloc_addr(
    vm_space_t* space,
    void* addr,
    size_t size,
    uint32_t flags,
    cache_type_t cache,
    size_t alignment
);

void vmfree(vm_space_t* space, void* ptr, size_t size);
extern vm_space_t kernel_space;

#ifdef __cplusplus
}
#endif

#endif