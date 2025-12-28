#ifndef KERNEL_MEMORY_VMM_H
#define KERNEL_MEMORY_VMM_H 1

#include "memory/pagemap.h"

#ifdef __cplusplus
extern "C" {
#endif

pagemap_t* vmm_get_kernel_pagemap(void);

void vmm_init(void);

#ifdef __cplusplus
}
#endif

#endif  // KERNEL_MEMORY_VMM_H