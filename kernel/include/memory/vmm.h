#ifndef KERNEL_MEMORY_VMM_H
#define KERNEL_MEMORY_VMM_H 1

#include "memory/pagemap.h"

void vmm_map_kernel(pagemap_t* map, uintptr_t kernel_base, uintptr_t phys_base_delta);

pagemap_t* vmm_get_kernel_pagemap(void);

void vmm_init(void);

#endif  // KERNEL_MEMORY_VMM_H