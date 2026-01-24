#ifndef KERNEL_MEMORY_PMM_H
#define KERNEL_MEMORY_PMM_H 1

#include <stdatomic.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

struct [[gnu::aligned(16)]] page {
    uintptr_t phys_addr;  // Physical address of the page

    atomic_uint_fast16_t ref_count;
    uint8_t order;  // Order of the block
    uint8_t flags;  // Status flags
};

typedef struct pmm_stats {
    size_t total_memory;
    size_t used_memory;
    size_t free_memory;
} pmm_stats_t;

void* pmm_alloc(size_t count);
void* pmm_alloc_aligned(size_t alignment, size_t count);
void* pmm_alloc_dma(size_t alignment, size_t count);

void pmm_free(void* ptr);
void pmm_get_stats(pmm_stats_t* stats);

void pmm_inc_ref(void* ptr);
void pmm_dec_ref(void* ptr);
uint16_t pmm_get_ref(void* ptr);

void pmm_init(void);

#ifdef __cplusplus
}
#endif

#endif