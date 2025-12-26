#include "memory/pmm.h"

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "arch.h"
#include "boot/boot.h"
#include "boot/limine.h"
#include "compiler.h"
#include "libs/log.h"
#include "libs/math.h"
#include "libs/spinlock.h"
#include "memory/memory.h"

#define CACHE_SIZE 512  // 2MB cache per CPU
#define BATCH_SIZE 256  // Transfer 1MB at a time between Global Bitmap <-> Local CPU Cache

typedef struct [[gnu::aligned(CACHE_LINE_SIZE)]] per_cpu_cache {
    uintptr_t* stack;
    size_t count;
    size_t capacity;
} per_cpu_cache_t;

static struct {
    uint64_t* bitmap;
    uint64_t* summary_bitmap;

    size_t total_pages;
    size_t summary_entries;
    size_t bitmap_entries;
    size_t used_pages;
    size_t low_mem_threshold_idx;
    size_t free_idx_hint;
    size_t align_idx_hint;

    per_cpu_cache_t* cpu_caches;
    size_t num_cpus;

    irq_lock_t irq_lock;
    interrupt_lock_t lock;  // IRQ + Spinlock
} pmm_state;

static inline void bitmap_set_bit(size_t idx) {
    ASSERT(pmm_state.bitmap && pmm_state.summary_bitmap);

    size_t byte = idx / UINT64_WIDTH;
    size_t bit  = idx % UINT64_WIDTH;

    pmm_state.bitmap[byte] |= (1ul << bit);

    // When a 64-page block transitions to "completely full", we mark it full in the summary bitmap.
    if (pmm_state.bitmap[byte] == UINT64_MAX) {
        size_t summary_byte = byte / UINT64_WIDTH;
        size_t summary_bit  = byte % UINT64_WIDTH;

        pmm_state.summary_bitmap[summary_byte] |= (1ul << summary_bit);
    }
}

static inline void bitmap_clear_bit(size_t idx) {
    ASSERT(pmm_state.bitmap && pmm_state.summary_bitmap);

    size_t byte         = idx / UINT64_WIDTH;
    size_t summary_byte = byte / UINT64_WIDTH;

    size_t bit         = idx % UINT64_WIDTH;
    size_t summary_bit = byte % UINT64_WIDTH;

    pmm_state.bitmap[byte] &= ~(1ul << bit);

    // Any cleared bit means this 64-page block is no longer "fully used". We eagerly clear the
    // summary bit so that future scans will see this region as a candidate without having to probe
    // the entire word first.
    pmm_state.summary_bitmap[summary_byte] &= ~(1ul << summary_bit);
}

static inline bool bitmap_test_bit(size_t idx) {
    ASSERT(pmm_state.bitmap);

    size_t byte = idx / UINT64_WIDTH;
    size_t bit  = idx % UINT64_WIDTH;

    return pmm_state.bitmap[byte] & (1ul << bit);
}

static inline bool summary_bitmap_test_bit(size_t idx) {
    ASSERT(pmm_state.summary_bitmap);

    size_t byte         = idx / UINT64_WIDTH;
    size_t summary_byte = byte / UINT64_WIDTH;

    size_t bit         = idx % UINT64_WIDTH;
    size_t summary_bit = byte % UINT64_WIDTH;

    return pmm_state.summary_bitmap[summary_byte] & (1ul << summary_byte);
}

static bool scan_bitmap_range(
    per_cpu_cache_t* cache,
    size_t start_idx,
    size_t end_idx,
    size_t need,
    size_t* collected
) {
    ASSERT(cache && collected);
    ASSERT(pmm_state.bitmap && pmm_state.summary_bitmap);

    size_t start = start_idx / UINT64_WIDTH;
    size_t end   = div_roundup(end_idx, UINT64_WIDTH);

    for (size_t s = start; s < end; ++s) {
        prefetch(&pmm_state.summary_bitmap[s + 2], 0, 1);

        // Skip the 64-page block if it is full
        if (pmm_state.summary_bitmap[s] == UINT64_MAX) {
            continue;
        }

        uint64_t summary_val = pmm_state.summary_bitmap[s];
        uint64_t summary_inv = ~summary_val;

        while (summary_inv) {
            int block_bit   = ctz(summary_inv);
            size_t word_idx = (s * UINT64_WIDTH) + (size_t)block_bit;

            if (word_idx >= end_idx) {
                return false;
            }

            prefetch(&pmm_state.bitmap[word_idx + 4], 1, 1);
            uint64_t word_val = pmm_state.bitmap[word_idx];

            // If word is not full, extract pages
            if (word_val != UINT64_MAX) {
                if (word_val == 0 && (need - *collected) >= 64) {
                    // Mark full
                    pmm_state.bitmap[word_idx] = UINT64_MAX;
                    pmm_state.summary_bitmap[s] |= (1ul << block_bit);

                    uint64_t base_page = word_idx * UINT64_WIDTH;

                    for (size_t j = 0; j < UINT64_WIDTH; ++j) {
                        cache->stack[cache->count++] = (base_page + j) * PAGE_SIZE_SMALL;
                    }

                    *collected += UINT64_WIDTH;
                } else {
                    uint64_t inv_word  = ~word_val;
                    bool word_modified = false;

                    while (inv_word && (*collected < need)) {
                        int page_bit    = ctz(inv_word);
                        size_t page_idx = (word_idx * UINT64_WIDTH) + (size_t)page_bit;

                        if (page_idx >= pmm_state.total_pages) {
                            return true;
                        }

                        // Add to CPU cache
                        cache->stack[cache->count++] = page_idx * PAGE_SIZE_SMALL;
                        (*collected)++;

                        word_val |= (1ul << page_bit);
                        inv_word &= ~(1ul << page_bit);

                        word_modified = true;
                    }

                    if (word_modified) {
                        pmm_state.bitmap[word_idx] = word_val;

                        if (word_val == UINT64_MAX) {
                            pmm_state.summary_bitmap[s] |= (1ul << block_bit);
                        }
                    }
                }

                if (*collected >= need) {
                    pmm_state.free_idx_hint = word_idx * UINT64_WIDTH;
                    return true;
                }
            }

            // Clear bit to move to next free word in this summary block
            summary_inv &= ~(1ul << block_bit);
        }
    }

    // Continue to next range
    return false;
}

static void cache_refill(per_cpu_cache_t* cache) {
    ASSERT(cache);
    ASSERT(pmm_state.bitmap && pmm_state.summary_bitmap);

    size_t need = BATCH_SIZE;

    if ((cache->count + need) > cache->capacity) {
        need = cache->capacity - cache->count;
    }

    if (need == 0) {
        return;
    }

    size_t collected = 0;
    size_t start_idx = pmm_state.free_idx_hint / UINT64_WIDTH;

    if ((pmm_state.low_mem_threshold_idx < pmm_state.total_pages) &&
        (pmm_state.free_idx_hint < pmm_state.low_mem_threshold_idx)) {
        start_idx = pmm_state.low_mem_threshold_idx / UINT64_WIDTH;
    }

    // Scan from Hint -> End of Memory
    if (!scan_bitmap_range(cache, start_idx, pmm_state.bitmap_entries, need, &collected)) {
        // Wrap Around (Scan from 0 -> Hint)
        scan_bitmap_range(cache, 0, start_idx, need, &collected);
    }

    pmm_state.used_pages += collected;
}

static int sort_cache(const void* a, const void* b) {
    ASSERT(a && b);

    const uintptr_t arg1 = *(const uintptr_t*)a;
    const uintptr_t arg2 = *(const uintptr_t*)b;

    if (arg1 < arg2) {
        return -1;
    } else if (arg1 > arg2) {
        return 1;
    }

    return 0;
}

static void cache_flush(per_cpu_cache_t* cache) {
    ASSERT(cache);
    ASSERT(pmm_state.bitmap && pmm_state.summary_bitmap);

    size_t target_count = cache->capacity / 2;

    if (cache->capacity <= target_count) {
        return;
    }

    size_t flush_count     = cache->capacity - target_count;
    uintptr_t* flush_start = &cache->stack[target_count];

    // Sort addresses in order, so they hit consecutive bitmap words.
    if (flush_count > 1) {
        qsort(flush_start, flush_count, sizeof(uintptr_t), sort_cache);
    }

    size_t last_word_idx   = UINT64_MAX;
    uint64_t curr_word_val = 0;
    bool is_dirty          = false;

    for (size_t i = 0; i < flush_count; ++i) {
        uintptr_t phys_addr = flush_start[i];
        size_t page_idx     = phys_addr / PAGE_SIZE_SMALL;

        if (page_idx >= pmm_state.total_pages) {
            continue;
        }

        size_t word_idx = page_idx / UINT64_WIDTH;
        size_t bit_idx  = page_idx % UINT64_WIDTH;

        uint64_t mask = (1ul << bit_idx);

        // If we moved to a new word, commit the previous one to the global state
        if (word_idx != last_word_idx) {
            if (is_dirty && (last_word_idx < pmm_state.bitmap_entries)) {
                const size_t last_word_byte = last_word_idx / UINT64_WIDTH;
                const size_t last_word_bit  = last_word_idx % UINT64_WIDTH;

                pmm_state.bitmap[last_word_idx] = curr_word_val;
                pmm_state.summary_bitmap[last_word_byte] &= ~(1ul << last_word_bit);
            }

            last_word_idx = word_idx;
            curr_word_val = pmm_state.bitmap[word_idx];
            is_dirty      = true;
        }

        // Clear the bit in the local copy
        if (curr_word_val & mask) {
            curr_word_val &= ~mask;
            pmm_state.used_pages--;
        }

        if (page_idx < pmm_state.free_idx_hint) {
            pmm_state.free_idx_hint = page_idx;
        }

        if (page_idx < pmm_state.align_idx_hint) {
            pmm_state.align_idx_hint = page_idx;
        }
    }

    if (is_dirty && (last_word_idx < pmm_state.bitmap_entries)) {
        const size_t last_word_byte = last_word_idx / UINT64_WIDTH;
        const size_t last_word_bit  = last_word_idx % UINT64_WIDTH;

        pmm_state.bitmap[last_word_idx] = curr_word_val;
        pmm_state.summary_bitmap[last_word_byte] &= ~(1ul << last_word_bit);
    }

    cache->count = target_count;
}

static void* pmm_alloc_from_bitmap(size_t count) {
    size_t start_idx = pmm_state.free_idx_hint;

    if ((pmm_state.low_mem_threshold_idx < pmm_state.total_pages) &&
        (start_idx < pmm_state.low_mem_threshold_idx)) {
        start_idx = pmm_state.low_mem_threshold_idx;
    }

    if (count == 1) {
        // Single-page allocations prefer to find a "mostly free" region
        // using the summary bitmap, then drill down into the main bitmap.
        size_t start         = start_idx / UINT64_WIDTH;
        size_t summary_start = start / UINT64_WIDTH;

        for (size_t s = summary_start; s < pmm_state.summary_entries; ++s) {
            prefetch(&pmm_state.summary_bitmap[s + 4], 0, 1);

            // Each summary entry covers 64 bitmap entries = 4096 pages.
            uint64_t summary_word = pmm_state.summary_bitmap[s];

            // Summary == all ones => every tracked 64-page block here is full.
            // Skipping avoids touching obviously-saturated regions at all.
            if (summary_word == UINT64_MAX) {
                continue;
            }

            // Find a bitmap word (block of 64 pages) with at least one free page.
            int block_offset = ctz(~summary_word);
            size_t map_idx   = (s * UINT64_WIDTH) + (size_t)block_offset;

            // Now verify the actual bitmap word and pick the first free page in it.
            if (map_idx < pmm_state.bitmap_entries) {
                prefetch(&pmm_state.bitmap[map_idx + 8], 0, 1);
                uint64_t entry = pmm_state.bitmap[map_idx];

                if (entry != UINT64_MAX) {
                    int bit_offset = ctz(~entry);
                    size_t idx     = (map_idx * UINT64_WIDTH) + (size_t)bit_offset;

                    if (idx < pmm_state.total_pages) {
                        bitmap_set_bit(idx);
                        pmm_state.used_pages++;
                        pmm_state.free_idx_hint = idx + 1;

                        return (void*)(idx * PAGE_SIZE_SMALL);
                    }
                }
            }
        }

        // Wrap around: if we started past 0, scan from 0 to the start hint.
        if (pmm_state.free_idx_hint > 0) {
            for (size_t s = 0; s < summary_start; ++s) {
                uint64_t summary_entry = pmm_state.summary_bitmap[s];

                if (summary_entry == UINT64_MAX) {
                    continue;
                }

                int block_offset = ctz(~summary_entry);
                size_t map_idx   = (s * UINT64_WIDTH) + (size_t)block_offset;

                if (map_idx < pmm_state.bitmap_entries) {
                    uint64_t entry = pmm_state.bitmap[map_idx];

                    if (entry != UINT64_MAX) {
                        int bit_offset = ctz(~entry);
                        size_t idx     = (map_idx * UINT64_WIDTH) + (size_t)bit_offset;

                        if (idx < pmm_state.total_pages) {
                            bitmap_set_bit(idx);
                            pmm_state.used_pages++;
                            pmm_state.free_idx_hint = idx + 1;

                            return (void*)(idx * PAGE_SIZE_SMALL);
                        }
                    }
                }
            }
        }
    }

    release_interrupt_lock(&pmm_state.lock);
    return pmm_alloc_aligned(PAGE_SIZE_SMALL, count);
}

static void* try_alloc_aligned(size_t start, size_t end, size_t count, size_t alignment) {
    size_t pages_per_alignment = alignment / PAGE_SIZE_SMALL;
    size_t curr                = align_up(start, pages_per_alignment);

    while (curr < end) {
        if ((curr + count) > pmm_state.total_pages) {
            break;
        }

        if ((curr % UINT64_WIDTH) == 0 && (count >= UINT64_WIDTH)) {
            size_t summary_idx = curr / (UINT64_WIDTH * UINT64_WIDTH);

            if ((summary_idx < pmm_state.summary_entries) &&
                (pmm_state.summary_bitmap[summary_idx] == UINT64_MAX)) {
                curr += (UINT64_MAX * UINT64_MAX);
                curr = align_up(curr, pages_per_alignment);
                continue;
            }
        }

        // Inner scan: Check if count pages starting at curr are free.
        bool fit = true;
        for (size_t i = 0; i < count; ++i) {
            if (bitmap_test_bit(curr + i)) {
                fit = false;

                // Found an allocated page at (curr + j); skip ahead to next alignment.
                curr = align_up(curr + i + 1, pages_per_alignment);
                break;
            }
        }

        if (fit) {
            for (size_t i = 0; i < count; ++i) {
                bitmap_set_bit(curr + i);
            }

            pmm_state.used_pages += count;

            if (alignment >= PAGE_SIZE_MEDIUM) {
                pmm_state.align_idx_hint = curr + count;
            } else {
                pmm_state.free_idx_hint = curr + count;
            }

            return (void*)(curr * PAGE_SIZE_SMALL);
        }
    }

    return nullptr;
}

void* pmm_alloc(size_t count) {
    if (count == 0) {
        return nullptr;
    }

    if ((count == 1) && pmm_state.cpu_caches) {
        acquire_irq_lock(&pmm_state.irq_lock);

        size_t core_id = arch_get_core_idx();

        if (core_id < pmm_state.num_cpus) {
            per_cpu_cache_t* cache = &pmm_state.cpu_caches[core_id];

            if (cache->count == 0) {
                acquire_interrupt_lock(&pmm_state.lock);
                cache_refill(cache);
                release_interrupt_lock(&pmm_state.lock);
            }

            if (cache->count > 0) {
                release_irq_lock(&pmm_state.irq_lock);
                return (void*)(cache->stack[--cache->count]);
            }
        }

        release_irq_lock(&pmm_state.irq_lock);
    }

    acquire_interrupt_lock(&pmm_state.lock);

    void* addr = pmm_alloc_from_bitmap(count);

    if (!addr) {
        KLOG_WARN("PMM alloc failed count=%zu\n", count);
    }

    release_interrupt_lock(&pmm_state.lock);
    return addr;
}

void* pmm_alloc_aligned(size_t alignment, size_t count) {
    if ((count == 0) || (alignment == 0) || !is_aligned(alignment, PAGE_SIZE_SMALL)) {
        return nullptr;
    }

    size_t start_hint = pmm_state.free_idx_hint;

    // Prefer High Memory
    if ((pmm_state.low_mem_threshold_idx < pmm_state.total_pages) &&
        (start_hint < pmm_state.low_mem_threshold_idx)) {
        start_hint = pmm_state.low_mem_threshold_idx;
    }

    // Use the aligned hint if alignment is large
    if (alignment >= PAGE_SIZE_MEDIUM) {
        start_hint = pmm_state.align_idx_hint;
    }

    acquire_interrupt_lock(&pmm_state.lock);

    void* res = try_alloc_aligned(start_hint, pmm_state.total_pages, count, alignment);

    if (!res) {
        res = try_alloc_aligned(0, start_hint, count, alignment);
    }

    if (!res) {
        KLOG_WARN("PMM alloc_aligned failed count=%zu align=0x%zx\n", count, alignment);
    }

    release_interrupt_lock(&pmm_state.lock);
    return res;
}

void* pmm_alloc_dma(size_t alignment, size_t count) {
    if ((count == 0) || (alignment == 0) || !is_aligned(alignment, PAGE_SIZE_SMALL)) {
        return nullptr;
    }

    size_t pages_per_alignment = alignment / PAGE_SIZE_SMALL;
    size_t limit               = pmm_state.low_mem_threshold_idx;
    size_t curr                = 0;

    acquire_interrupt_lock(&pmm_state.lock);

    while (curr < limit) {
        if ((curr + count) > limit) {
            break;
        }

        if ((curr % UINT64_WIDTH) == 0 && (count >= UINT64_WIDTH)) {
            size_t summary_idx = curr / (UINT64_WIDTH * UINT64_WIDTH);

            if ((summary_idx < pmm_state.summary_entries) &&
                (pmm_state.summary_bitmap[summary_idx] == ~0ul)) {
                curr += (UINT64_WIDTH * UINT64_WIDTH);
                curr = align_up(curr, pages_per_alignment);
                continue;
            }
        }

        bool fit = true;
        for (size_t i = 0; i < count; ++i) {
            if (bitmap_test_bit(curr + i)) {
                fit = false;

                // Found an allocated page at (curr + j); skip ahead to next alignment.
                curr = align_up(curr + i + 1, pages_per_alignment);
                break;
            }
        }

        if (fit) {
            for (size_t i = 0; i < count; ++i) {
                bitmap_set_bit(curr + i);
            }

            pmm_state.used_pages += count;

            release_interrupt_lock(&pmm_state.lock);
            return (void*)(curr * PAGE_SIZE_SMALL);
        }
    }

    release_interrupt_lock(&pmm_state.lock);
    return nullptr;
}

static void pmm_free_to_bitmap(size_t page_idx, size_t count) {
    size_t curr      = page_idx;
    size_t remaining = count;

    // Free individual bits until 64-page aligned
    while ((remaining > 0) && (curr % UINT64_WIDTH) != 0) {
        if ((curr < pmm_state.total_pages) && bitmap_test_bit(curr)) {
            bitmap_clear_bit(curr);
            pmm_state.used_pages--;
        }

        curr++;
        remaining--;
    }

    // Free 64 pages at a time using word writes
    while (remaining >= UINT64_WIDTH) {
        size_t word_idx = curr / UINT64_WIDTH;

        if (word_idx < pmm_state.bitmap_entries) {
            uint64_t old_val = pmm_state.bitmap[word_idx];

            if (old_val != 0) {
                const size_t byte = word_idx / UINT64_WIDTH;
                const size_t bit  = word_idx % UINT64_WIDTH;

                // Count how many bits are flipped from 1->0
                pmm_state.used_pages -= (size_t)(popcount(old_val));
                pmm_state.bitmap[word_idx] = 0;

                pmm_state.summary_bitmap[byte] &= ~(1ul << bit);
            }
        }

        curr += UINT64_WIDTH;
        remaining -= UINT64_WIDTH;
    }

    // Free remaining individual bits
    while (remaining > 0) {
        if ((curr < pmm_state.total_pages) && bitmap_test_bit(curr)) {
            bitmap_clear_bit(curr);
            pmm_state.used_pages--;
        }

        curr++;
        remaining--;
    }

    // Hint Update
    if ((page_idx < pmm_state.free_idx_hint) && (page_idx > pmm_state.low_mem_threshold_idx)) {
        pmm_state.free_idx_hint = page_idx;
    }
}

void pmm_free(void* ptr, size_t count) {
    if (ptr == nullptr) {
        return;
    }

    if ((count == 1) && (pmm_state.cpu_caches)) {
        acquire_irq_lock(&pmm_state.irq_lock);

        size_t core_id = arch_get_core_idx();

        if (core_id < pmm_state.num_cpus) {
            per_cpu_cache_t* cache = &pmm_state.cpu_caches[core_id];

            if (cache->count >= cache->capacity) {
                acquire_interrupt_lock(&pmm_state.lock);
                cache_flush(cache);
                release_interrupt_lock(&pmm_state.lock);
            }

            // Prevent Double-free in local cache
            for (size_t i = 0; i < cache->count; ++i) {
                if (cache->stack[i] == (uintptr_t)ptr) {
                    return;
                }
            }

            cache->stack[cache->count++] = (uintptr_t)ptr;

            release_irq_lock(&pmm_state.irq_lock);
            return;
        }

        release_irq_lock(&pmm_state.irq_lock);
    }

    acquire_interrupt_lock(&pmm_state.lock);
    pmm_free_to_bitmap((uintptr_t)ptr / PAGE_SIZE_SMALL, count);
    release_interrupt_lock(&pmm_state.lock);
}

void pmm_get_stats(pmm_stats_t* stats) {
    acquire_interrupt_lock(&pmm_state.lock);

    size_t cached_total = 0;

    for (size_t i = 0; i < pmm_state.num_cpus; ++i) {
        cached_total += pmm_state.cpu_caches[i].count;
    }

    size_t actual_used  = pmm_state.used_pages - cached_total;
    stats->total_memory = pmm_state.total_pages * PAGE_SIZE_SMALL;
    stats->used_memory  = actual_used * PAGE_SIZE_SMALL;
    stats->free_memory  = (pmm_state.total_pages - actual_used) * PAGE_SIZE_SMALL;

    release_interrupt_lock(&pmm_state.lock);
}

void pmm_init(void) {
    if (!(memmap_request.response) || !(memmap_request.response->entries)) {
        PANIC("Limine Memory Map not found!\n");
    }

    size_t memmap_count                  = memmap_request.response->entry_count;
    struct limine_memmap_entry** memmaps = memmap_request.response->entries;

    release_interrupt_lock(&pmm_state.lock);

    if (mp_request.response && (mp_request.response->cpu_count > 0)) {
        pmm_state.num_cpus = mp_request.response->cpu_count;
    } else {
        pmm_state.num_cpus = 1;
    }

    uintptr_t highest_addr = 0;

    // Find the highest address among usable/reclaimable types.
    for (size_t i = 0; i < memmap_count; ++i) {
        struct limine_memmap_entry* entry = memmaps[i];

        bool is_candidate = entry->type == LIMINE_MEMMAP_USABLE ||
                            entry->type == LIMINE_MEMMAP_BOOTLOADER_RECLAIMABLE ||
                            entry->type == LIMINE_MEMMAP_EXECUTABLE_AND_MODULES ||
                            entry->type == LIMINE_MEMMAP_ACPI_RECLAIMABLE;

        if (is_candidate) {
            uintptr_t end = entry->base + entry->length;

            if (end > highest_addr) {
                highest_addr = end;
            }
        }
    }

    pmm_state.total_pages           = div_roundup(highest_addr, PAGE_SIZE_SMALL);
    pmm_state.low_mem_threshold_idx = (PAGE_SIZE_LARGE * 4) / PAGE_SIZE_SMALL;

    // Clam threshold if system has less than 4GB RAM
    if (pmm_state.low_mem_threshold_idx > pmm_state.total_pages) {
        pmm_state.low_mem_threshold_idx = pmm_state.total_pages;
    }

    KLOG_INFO(
        "PMM: highest_addr=0x%lx total_pages=%zu low_memory_threshold_page=%zu\n",
        highest_addr,
        pmm_state.total_pages,
        pmm_state.low_mem_threshold_idx
    );

    size_t bitmap_size       = align_up(div_roundup(pmm_state.total_pages, 8u), 8u);
    pmm_state.bitmap_entries = bitmap_size / 8;

    // Summary bitmap: one bit per bitmap entry (i.e., per 64‑page block).
    size_t summary_bits       = pmm_state.bitmap_entries;
    size_t summary_size       = align_up(div_roundup(summary_bits, 8u), 8u);
    pmm_state.summary_entries = summary_size / 8;

    // `N` CPU stack cache size (for per-cpu cache).
    size_t cache_size  = pmm_state.num_cpus * sizeof(per_cpu_cache_t);
    size_t stack_bytes = pmm_state.num_cpus * (CACHE_SIZE * sizeof(uintptr_t));

    size_t total_metadata_bytes = bitmap_size + summary_size + cache_size + stack_bytes;

    KLOG_DEBUG(
        "PMM: bitmap_bytes=%zu summary_bytes=%zu cpu_cache_bytes=%zu stack_bytes=%zu "
        "metadata_total=%zu\n",
        bitmap_size,
        summary_size,
        cache_size,
        stack_bytes,
        total_metadata_bytes
    );

    // Find suitable hole for metadata. The idea is to place metadata in a
    // contiguous region that we then remove from the general pool, so the
    // allocator never hands it out by accident.
    struct limine_memmap_entry* best_candidate = nullptr;

    for (size_t i = 0; i < memmap_count; ++i) {
        struct limine_memmap_entry* entry = memmaps[i];

        // Reject 0x0 base
        if (entry->base == 0) {
            continue;
        }

        if (entry->type == LIMINE_MEMMAP_USABLE && entry->length >= total_metadata_bytes) {
            if (!best_candidate || (entry->base > best_candidate->base)) {
                best_candidate = entry;
            }
        }
    }

    if (!best_candidate) {
        // If no high memory found, check for any suitable memory.
        for (size_t i = 0; i < memmap_count; ++i) {
            struct limine_memmap_entry* entry = memmaps[i];

            if (entry->type == LIMINE_MEMMAP_USABLE && entry->length >= total_metadata_bytes) {
                best_candidate = entry;
                break;
            }
        }
    }

    if (best_candidate == nullptr) {
        PANIC("No suitable memory hole found for metadata of size 0x%lx\n", total_metadata_bytes);
    }

    uintptr_t meta_base = best_candidate->base;
    KLOG_INFO(
        "PMM: using metadata base phys=0x%lx (region base=0x%lx len=0x%lx)\n",
        meta_base,
        best_candidate->base,
        best_candidate->length
    );

    if (meta_base == 0) {
        meta_base += PAGE_SIZE_SMALL;
        best_candidate->length -= PAGE_SIZE_SMALL;

        if (best_candidate->length < total_metadata_bytes) {
            PANIC(
                "No suitable memory hole found for metadata of size 0x%lx\n",
                total_metadata_bytes
            );
        }
    }

    // Reserve metadata region: we move the Limine entry forward so the
    // rest of the kernel never sees that region as free RAM.
    void* metadata_phys = (void*)meta_base;
    best_candidate->base += total_metadata_bytes;
    best_candidate->length -= total_metadata_bytes;

    uintptr_t metadata_addr = to_higher_half((uintptr_t)metadata_phys);

    // Layout: [bitmap][summary bitmap][cpu cache][cpu stack cache]
    pmm_state.bitmap         = (uint64_t*)metadata_addr;
    pmm_state.summary_bitmap = (uint64_t*)(metadata_addr + bitmap_size);

    pmm_state.cpu_caches = (per_cpu_cache_t*)(metadata_addr + bitmap_size + summary_size);

    uintptr_t* stack_start = (uintptr_t*)(metadata_addr + bitmap_size + summary_size + cache_size);

    for (size_t i = 0; i < pmm_state.num_cpus; ++i) {
        pmm_state.cpu_caches[i].count    = 0;
        pmm_state.cpu_caches[i].capacity = CACHE_SIZE;
        pmm_state.cpu_caches[i].stack    = stack_start + (i * CACHE_SIZE);
    }

    KLOG_DEBUG(
        "PMM: bitmap@%p (%zu entries), summary@%p (%zu entries), cpu cache@%p (%zu cpu caches)\n",
        pmm_state.bitmap,
        pmm_state.bitmap_entries,
        pmm_state.summary_bitmap,
        pmm_state.summary_entries,
        pmm_state.cpu_caches,
        pmm_state.num_cpus
    );

    // Initially mark all pages as used; we will then free only the
    // ranges that Limine reports as usable. This ensures we never
    // accidentally treat "unknown" memory as allocatable.
    memset(pmm_state.bitmap, 0xff, bitmap_size);
    memset(pmm_state.summary_bitmap, 0xff, summary_size);
    pmm_state.used_pages = pmm_state.total_pages;

    if (pmm_state.total_pages > pmm_state.low_mem_threshold_idx) {
        pmm_state.free_idx_hint = pmm_state.low_mem_threshold_idx;
    } else {
        pmm_state.free_idx_hint = 0;
    }

    pmm_state.align_idx_hint = pmm_state.free_idx_hint;

    // Populate free memory from Limine map by freeing all usable pages.
    size_t reclaimed_pages = 0;
    for (size_t i = 0; i < memmap_count; ++i) {
        struct limine_memmap_entry* entry = memmaps[i];

        if (entry->type == LIMINE_MEMMAP_USABLE) {
            uintptr_t base = entry->base;
            size_t len     = entry->length;

            if (base == 0) {
                if (len >= PAGE_SIZE_SMALL) {
                    base += PAGE_SIZE_SMALL;
                    len -= PAGE_SIZE_SMALL;
                } else {
                    continue;
                }
            }

            size_t pages = len / PAGE_SIZE_SMALL;
            reclaimed_pages += pages;

            if (len > 0) {
                pmm_free((void*)base, pages);
            }
        }
    }

    // Restore `best_candidate` to original size
    best_candidate->base -= total_metadata_bytes;
    best_candidate->length += total_metadata_bytes;

    // Mystery `\t` character appears
    pmm_stats_t stats;
    pmm_get_stats(&stats);

    KLOG_INFO(
        "PMM initialized: total_pages=%zu (~%zu MiB), reclaimed=%zu pages, free=%zu MiB\n",
        pmm_state.total_pages,
        (pmm_state.total_pages * PAGE_SIZE_SMALL) >> 20,
        reclaimed_pages,
        stats.free_memory >> 20
    );
}