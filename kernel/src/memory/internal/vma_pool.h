#ifndef KERNEL_MEMORY_INTERNAL_VMA_POOL_H
#define KERNEL_MEMORY_INTERNAL_VMA_POOL_H 1

#include "memory/vma.h"

void vma_pool_init(vm_space_t* space);
vm_area_t* vma_new(vm_space_t* space);
void vma_free_struct(vm_space_t* space, vm_area_t* vma);

#endif