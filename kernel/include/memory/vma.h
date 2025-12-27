
#include "libs/spinlock.h"
#ifndef KERNEL_MEMORY_VMA_H
#define KERNEL_MEMORY_VMA_H 1

#include "memory/pagemap.h"

typedef struct vm_area {
    uintptr_t start;
    uintptr_t end;  // Exclusive: [Start, end)
    size_t size;
    size_t page_size;

    uint32_t flags;
    cache_type_t cache;

    struct vm_area* rb_parent;
    struct vm_area* rb_right;
    struct vm_area* rb_left;
    int rb_color;

    struct vm_area* next_free;
} vm_area_t;

typedef struct {
    vm_area_t* root;
    pagemap_t* map;

    interrupt_lock_t lock;
    uintptr_t allocation_hint;

    uintptr_t start_limit;
    uintptr_t end_limit;

    uintptr_t alloc_hint;
    vm_area_t* cached_vma;
} vm_space_t;

void vmm_init_global(void);

void vmm_init_space(vm_space_t* space, pagemap_t* map, uintptr_t start, uintptr_t end);
void* vmm_alloc(
    vm_space_t* space,
    size_t size,
    uint32_t flags,
    cache_type_t cache,
    size_t alignment
);
void vmm_free(vm_space_t* space, void* ptr);
bool vmm_handle_fault(vm_space_t* space, uintptr_t addr, uint32_t error_code);
vm_area_t* vmm_find_vma(vm_space_t* space, uintptr_t addr);

extern vm_space_t kernel_space;

#endif