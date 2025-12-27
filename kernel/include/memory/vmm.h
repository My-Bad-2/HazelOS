#ifndef KERNEL_MEMORY_VMM_H
#define KERNEL_MEMORY_VMM_H 1

#include "memory/pagemap.h"

pagemap_t* vmm_get_kernel_pagemap(void);

void vmm_init(void);

#endif  // KERNEL_MEMORY_VMM_H