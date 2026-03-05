#ifndef KERNEL_MEMORY_PMM_H
#define KERNEL_MEMORY_PMM_H 1

#include <stdatomic.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define PAGE_FLAG_SLAB (1 << 4)

struct [[gnu::aligned(16)]] page {
    uint8_t order;  // Order of the block
    uint8_t flags;  // Zone ID, Used, etc.

    union {
        struct {
            _Atomic(uint16_t) ref_count;
            uint32_t section_idx;
        } buddy;

        struct {
            struct slab* slab_data;
        } slab;
    };
};

typedef struct pmm_stats {
    size_t total_memory;
    size_t used_memory;
    size_t free_memory;
} pmm_stats_t;

struct page* phys_to_page(uintptr_t phys);

void* pmm_alloc(size_t count);
void* pmm_alloc_aligned(size_t alignment, size_t count);
size_t pmm_alloc_bulk(size_t count, int order, void** pages);

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