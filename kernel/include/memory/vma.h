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

#define MAP_HUGE_SHIFT 26
#define MAP_HUGE_MASK  0x3f

#define PROT_NONE  0
#define PROT_EXEC  0x01
#define PROT_READ  0x02
#define PROT_WRITE 0x04

#define MAP_SHARED    0x01
#define MAP_PRIVATE   0x02
#define MAP_ANONYMOUS 0x04
#define MAP_FIXED     0x08
#define MAP_GROWSDOWN 0x10
#define MAP_HUGETLB   0x20
#define MAP_POPULATE  0x40
#define MAP_STACK     0x80

#define MAP_HUGE_2MB (21 << MAP_HUGE_SHIFT)
#define MAP_HUGE_1GB (30 << MAP_HUGE_SHIFT)

void* sys_mmap(
    vm_space_t* space,
    void* addr,
    size_t length,
    int prot,
    int flags,
    int fd,
    long offset
);
int sys_munmmap(vm_space_t* space, void* addr, size_t length);
int sys_mprotect(vm_space_t* space, void* addr, size_t size, int prot);

#ifdef __cplusplus
}
#endif

#endif