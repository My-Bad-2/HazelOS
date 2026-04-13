#ifndef KERNEL_MEMORY_VMM_H
#define KERNEL_MEMORY_VMM_H 1

#include "memory/pagemap.h"

#define USER_SPACE_START 0x10000ul

#ifdef __cplusplus
extern "C" {
#endif

pagemap_t* vmm_get_kernel_pagemap(void);

void vmm_map_kernel(pagemap_t* map, uintptr_t kernel_base, uintptr_t phys_base_delta);
void vmm_init(void);

const uintptr_t get_user_space_end_limit(void);
const uintptr_t get_kernel_space_start_limit(void);

#ifdef __cplusplus
}
#endif

#endif  // KERNEL_MEMORY_VMM_H