#include "memory/pmm.h"

#include <stddef.h>
#include <stdint.h>

#include "memory/memory.h"
#include "tests/runner.h"

#if KERNEL_TEST

TEST(pmm_alloc_basic, "Basic Page Allocation") {
    // Single page
    void* p1 = pmm_alloc(1);
    TEST_ASSERT(p1 != nullptr);
    TEST_ASSERT(((uintptr_t)p1 & 0xFFF) == 0);  // 4KB alignment check

    // Distinct page
    void* p2 = pmm_alloc(1);
    TEST_ASSERT(p2 != nullptr);
    TEST_ASSERT(p1 != p2);

    pmm_free(p1, 1);
    pmm_free(p2, 1);
}

TEST(pmm_alloc_aligned, "Aligned Allocation (2MB)") {
    size_t align_2mb = PAGE_SIZE_MEDIUM;

    // Attempt 2MB alloc
    void* huge_page = pmm_alloc_aligned(align_2mb, 1);

    // It's valid to return null if OOM/Fragmented, but if we get a pointer, check align
    if (huge_page) {
        TEST_ASSERT(((uintptr_t)huge_page % align_2mb) == 0);
        pmm_free(huge_page, 1);
    }

    // Attempt 64KB alloc (multiple pages)
    size_t align_64kb = PAGE_SIZE_SMALL * 16;
    void* p3          = pmm_alloc_aligned(align_64kb, 3);
    TEST_ASSERT(p3 != nullptr);
    TEST_ASSERT(((uintptr_t)p3 % align_64kb) == 0);

    pmm_free(p3, 3);
}

TEST(pmm_alloc_dma, "DMA < 4GB Constraints") {
    uintptr_t limit_4gb = PAGE_SIZE_LARGE;

    // Basic DMA
    void* d1 = pmm_alloc_dma(PAGE_SIZE_SMALL, 1);
    TEST_ASSERT(d1 != nullptr);
    TEST_ASSERT((uintptr_t)d1 < limit_4gb);

    // Aligned DMA
    void* d2 = pmm_alloc_dma(PAGE_SIZE_SMALL * 16, 1);
    TEST_ASSERT(d2 != nullptr);
    TEST_ASSERT((uintptr_t)d2 < limit_4gb);
    TEST_ASSERT(((uintptr_t)d2 % 65536) == 0);

    // Batch DMA
    size_t pages = 16;
    void* d3     = pmm_alloc_dma(PAGE_SIZE_SMALL, pages);
    TEST_ASSERT(d3 != nullptr);

    // Ensure the end of the block is also < 4GB
    TEST_ASSERT(((uintptr_t)d3 + (pages * PAGE_SIZE_SMALL)) <= limit_4gb);

    pmm_free(d1, 1);
    pmm_free(d2, 1);
    pmm_free(d3, pages);
}

TEST(pmm_cache_churn, "Per-CPU Cache Churn") {
    // Stress test the refill/flush mechanics of the per-cpu cache
    constexpr int TEST_SIZE = 514;  // > 512 cache size
    void* ptrs[TEST_SIZE];

    // Refill Logic Trigger
    for (int i = 0; i < TEST_SIZE; i++) {
        ptrs[i] = pmm_alloc(1);
        TEST_ASSERT(ptrs[i] != nullptr);
    }

    // Flush Logic Trigger
    for (int i = 0; i < TEST_SIZE; i++) {
        pmm_free(ptrs[i], 1);
    }
}

TEST(pmm_fragmentation, "Fragmentation & Gap Filling") {
    // Create a scenario: Alloc A, Alloc B, Alloc C. Free B. Alloc D.
    // Use aligned to bypass per-cpu cache for predictable bitmap behavior.
    void* a = pmm_alloc_aligned(PAGE_SIZE_SMALL, 1);
    void* b = pmm_alloc_aligned(PAGE_SIZE_SMALL, 2);
    void* c = pmm_alloc_aligned(PAGE_SIZE_SMALL, 1);

    TEST_ASSERT(a && b && c);

    // Create hole
    pmm_free(b, 2);

    // Fill hole
    void* d = pmm_alloc_aligned(PAGE_SIZE_SMALL, 2);
    TEST_ASSERT(d != nullptr);

    pmm_free(a, 1);
    pmm_free(c, 1);
    pmm_free(d, 2);
}

TEST(pmm_bulk_boundary, "Bulk Word-Boundary Logic") {
    // Offset to ensure we aren't purely aligned at start
    void* offset = pmm_alloc(1);

    // Alloc 64 pages (Exactly 1 word in bitmap)
    void* p64 = pmm_alloc(64);
    TEST_ASSERT(p64 != nullptr);

    // Alloc 65 pages (1 word + 1 bit, triggers split logic)
    void* p65 = pmm_alloc(65);
    TEST_ASSERT(p65 != nullptr);

    pmm_free(p65, 65);
    pmm_free(p64, 64);
    pmm_free(offset, 1);
}

TEST(pmm_leak_check, "Zero Leakage Check") {
    // Snapshot stats
    pmm_stats_t start;
    pmm_get_stats(&start);

    // Do work
    void* p = pmm_alloc(100);
    TEST_ASSERT(p != nullptr);
    pmm_free(p, 100);

    // Check stats
    pmm_stats_t end;
    pmm_get_stats(&end);

    // Free memory should be identical
    TEST_ASSERT(start.free_memory == end.free_memory);
    TEST_ASSERT(start.used_memory == end.used_memory);
}

TEST(pmm_input_validation, "Input Validation (Invalid Args)") {
    // Allocation of 0 pages
    void* p1 = pmm_alloc(0);
    TEST_ASSERT(p1 == nullptr);

    // Aligned allocation of 0 pages
    void* p2 = pmm_alloc_aligned(PAGE_SIZE_SMALL, 0);
    TEST_ASSERT(p2 == nullptr);

    // Aligned allocation with invalid alignment (0)
    void* p3 = pmm_alloc_aligned(0, 1);
    TEST_ASSERT(p3 == nullptr);

    // Aligned allocation with non-power-of-2 alignment (e.g., 4097)
    // Note: implementation checks (align % PAGE_SIZE != 0), so 4097 fails.
    // What about 8192 + PAGE_SIZE_SMALL = 12288? It is page aligned but weird.
    // The allocator should technically handle any page-aligned boundary.
    // Let's test a misaligned one.
    void* p4 = pmm_alloc_aligned(4097, 1);
    TEST_ASSERT(p4 == nullptr);

    // Freeing nullptr
    pmm_free(nullptr, 1);

    // Freeing 0 count
    void* p5 = pmm_alloc(1);
    TEST_ASSERT(p5 != nullptr);

    pmm_free(p5, 0);  // Should be no-op
    pmm_free(p5, 1);  // Clean up
}

TEST(pmm_double_free_safety, "Double Free Safety") {
    // Verifies that freeing the same page twice does not corrupt stats
    // or the bitmap state (i.e., used_pages shouldn't decrement twice).
    pmm_stats_t start;
    pmm_get_stats(&start);

    // Alloc 1 page
    void* p = pmm_alloc(1);
    TEST_ASSERT(p != nullptr);

    // Free Once
    pmm_free(p, 1);

    // Free Twice
    pmm_free(p, 1);

    pmm_stats_t end;
    pmm_get_stats(&end);

    // Stats should be identical to start (alloc + free + free == alloc + free)
    TEST_ASSERT(start.used_memory == end.used_memory);
    TEST_ASSERT(start.free_memory == end.free_memory);
}

TEST(pmm_out_of_bounds_free, "Out of Bounds Free") {
    // Try to free a physical address clearly outside RAM (e.g., 64-bit max)
    // This ensures the allocator bounds-checks the address against total_pages
    // before trying to access the bitmap.

    // High canonical, way out of phys RAM range
    void* invalid_addr = (void*)0xFFFFFFFFFFFFF000ULL;
    pmm_free(invalid_addr, 1);
    // Assertion is that we didn't Page Fault or Panic.
}

TEST(pmm_summary_consistency, "Summary Bitmap Consistency") {
    // This forces the fill-up of a complete Superblock (64 pages * 64 bits = 4096 pages)
    // To safely test this without OOM, we alloc a smaller chunk that definitely covers
    // a single Summary bit transition (64 pages).
    size_t count = 64;
    void* chunk  = pmm_alloc(count);  // Should claim a full word

    // If we managed to alloc 64 aligned pages, the underlying word is now UINT64_MAX (All Used).
    // The summary bit logic should have set the summary bit.
    // While we can't inspect private state, we can verify we can free it safely
    // and re-alloc it.
    TEST_ASSERT(chunk != nullptr);
    pmm_free(chunk, count);

    // Re-alloc to ensure the summary bit was cleared correctly on free
    void* chunk2 = pmm_alloc(count);
    TEST_ASSERT(chunk2 != nullptr);

    pmm_free(chunk2, count);
}

TEST(pmm_ref_basic, "Ref-Count Basic Increment/Decrement") {
    void* p = pmm_alloc(1);
    TEST_ASSERT(p != nullptr);

    uint32_t initial_ref = pmm_get_ref(p);
    TEST_ASSERT(initial_ref == 1);

    uint32_t r1 = pmm_inc_ref(p);
    TEST_ASSERT(r1 == 2);
    TEST_ASSERT(pmm_get_ref(p) == 2);

    uint32_t r2 = pmm_dec_ref(p);
    TEST_ASSERT(r2 == 1);
    TEST_ASSERT(pmm_get_ref(p) == 1);

    pmm_free(p, 1);
}

TEST(pmm_ref_protection, "Ref-Count Prevents Premature Free") {
    pmm_stats_t start_stats;
    pmm_get_stats(&start_stats);

    void* p = pmm_alloc(1);
    TEST_ASSERT(p != nullptr);

    pmm_inc_ref(p);  // Ref=2
    TEST_ASSERT(pmm_get_ref(p) == 2);

    pmm_free(p, 1);

    TEST_ASSERT(pmm_get_ref(p) == 1);

    pmm_stats_t mid_stats;
    pmm_get_stats(&mid_stats);

    TEST_ASSERT(mid_stats.free_memory == start_stats.free_memory - PAGE_SIZE_SMALL);
    pmm_free(p, 1);

    pmm_stats_t end_stats;
    pmm_get_stats(&end_stats);

    TEST_ASSERT(end_stats.free_memory == start_stats.free_memory);
}

TEST(pmm_ref_saturation, "Ref-Count Saturation (Sticky 0xFFFF)") {
    void* p = pmm_alloc(1);
    TEST_ASSERT(p != nullptr);

    for (int i = 0; i < 65534; i++) {
        pmm_inc_ref(p);
    }

    TEST_ASSERT(pmm_get_ref(p) == 0xFFFF);

    // Attempt to overflow
    uint32_t val = pmm_inc_ref(p);
    TEST_ASSERT(val == 0xFFFF);
    TEST_ASSERT(pmm_get_ref(p) == 0xFFFF);

    // Attempt to free (decrement)
    uint32_t dec_val = pmm_dec_ref(p);
    TEST_ASSERT(dec_val == 0xFFFF);  // Should still be max
    TEST_ASSERT(pmm_get_ref(p) == 0xFFFF);

    // Verify free() doesn't reclaim it
    pmm_stats_t before_free;
    pmm_get_stats(&before_free);

    pmm_free(p, 1);
    pmm_stats_t after_free;
    pmm_get_stats(&after_free);

    TEST_ASSERT(before_free.free_memory == after_free.free_memory);

    // Note: We cannot clean this page up now via standard API. It is leaked by design.
    // This is acceptable for the test page.
}

TEST(pmm_ref_manual_dec_consistency, "Ref-Count Manual Dec -> Free Interaction") {
    void* p = pmm_alloc(1);

    // This leaves the page in a zombie state: Ref=0, but Bitmap=Used.
    uint32_t ref = pmm_dec_ref(p);
    TEST_ASSERT(ref == 0);

    // This should successfully clean up the zombie page.
    pmm_free(p, 1);

    // Verify it was actually freed by checking if we can alloc it again (LIFO cache)
    // or by stats.
    void* p2 = pmm_alloc(1);

    // Should get same address from hot cache
    TEST_ASSERT(p2 == p);

    pmm_free(p2, 1);
}

TEST(pmm_force_recover, "Recover Saturated Page") {
    void* p = pmm_alloc(1);

    for (int i = 0; i < 70000; i++) {
        pmm_inc_ref(p);
    }

    TEST_ASSERT(pmm_get_ref(p) == 0xFFFF);

    pmm_stats_t s1;
    pmm_get_stats(&s1);
    pmm_free(p, 1);
    pmm_stats_t s2;
    pmm_get_stats(&s2);
    TEST_ASSERT(s1.free_memory == s2.free_memory);  // Still leaked

    pmm_force_free(p, 1);

    pmm_stats_t s3;
    pmm_get_stats(&s3);
    TEST_ASSERT(s3.free_memory == s1.free_memory + PAGE_SIZE_SMALL);  // Recovered!

    void* p2 = pmm_alloc(1);
    TEST_ASSERT(p == p2);               // Should come back from LIFO cache
    TEST_ASSERT(pmm_get_ref(p2) == 1);  // Refcount should be reset to 1

    pmm_free(p2, 1);
}

#endif