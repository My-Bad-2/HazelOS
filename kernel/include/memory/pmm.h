#ifndef KERNEL_MEMORY_PMM_H
#define KERNEL_MEMORY_PMM_H 1

#include <stddef.h>

typedef struct pmm_stats {
    size_t total_memory;
    size_t used_memory;
    size_t free_memory;
} pmm_stats_t;

void* pmm_alloc(size_t count);
void* pmm_alloc_aligned(size_t alignment, size_t count);
void* pmm_alloc_dma(size_t alignment, size_t count);

void pmm_free(void* ptr, size_t count);
void pmm_get_stats(pmm_stats_t* stats);

void pmm_init(void);

#endif