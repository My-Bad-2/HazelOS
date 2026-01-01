#include "memory/heap.h"

#include "libs/math.h"
#include "memory/memory.h"
#include "memory/pagemap.h"
#include "memory/vma.h"
#include "tests/runner.h"

#if KERNEL_TEST

static void pattern_fill(void* ptr, size_t size, uint8_t seed) {
    uint8_t* p = (uint8_t*)ptr;

    for (size_t i = 0; i < size; i++) {
        p[i] = (uint8_t)(seed + i);
    }
}

static bool pattern_check(void* ptr, size_t size, uint8_t seed) {
    uint8_t* p = (uint8_t*)ptr;

    for (size_t i = 0; i < size; i++) {
        if (p[i] != (uint8_t)(seed + i)) return false;
    }

    return true;
}

TEST(heap_basic_alloc, "Heap: Basic kmalloc and kfree functionality") {
    size_t size = 32;
    void* ptr   = kmalloc(size);

    TEST_ASSERT(ptr != NULL);
    TEST_ASSERT(is_aligned((uintptr_t)ptr, 16));

    pattern_fill(ptr, size, 0xAA);
    TEST_ASSERT(pattern_check(ptr, size, 0xAA));

    kfree(ptr, size);
}

TEST(heap_alignment_promotion, "Heap: aligned_kalloc alignment verification") {
    void* p1 = aligned_kalloc(64, 16);
    TEST_ASSERT(p1 != NULL);
    TEST_ASSERT(is_aligned((uintptr_t)p1, 64));

    void* p2 = aligned_kalloc(4096, 32);
    TEST_ASSERT(p2 != NULL);
    TEST_ASSERT(is_aligned((uintptr_t)p2, 4096));

    kfree(p1, 16);
    kfree(p2, 32);
}

TEST(heap_magazine_refill, "Heap: Exhaust magazine to trigger backend refill") {
    const int count = 80;
    void* ptrs[80];

    for (int i = 0; i < count; i++) {
        ptrs[i] = kmalloc(32);
        TEST_ASSERT(ptrs[i] != NULL);

        *(volatile int*)ptrs[i] = i;
    }

    for (int i = 0; i < count; i++) {
        TEST_ASSERT(*(volatile int*)ptrs[i] == i);

        for (int j = i + 1; j < count; j++) {
            TEST_ASSERT(ptrs[i] != ptrs[j]);
        }
    }

    for (int i = 0; i < count; i++) {
        kfree(ptrs[i], 32);
    }
}

TEST(heap_large_alloc, "Heap: Large allocation VMM pass-through") {
    size_t large_sz = PAGE_SIZE_MEDIUM;
    void* huge_ptr  = kmalloc(large_sz);

    TEST_ASSERT(huge_ptr != nullptr);
    TEST_ASSERT(is_aligned((uintptr_t)huge_ptr, 16));

    pattern_fill(huge_ptr, large_sz, 0x55);
    TEST_ASSERT(pattern_check(huge_ptr, large_sz, 0x55));

    kfree(huge_ptr, large_sz);
}

TEST(heap_edge_cases, "Heap: Zero size and invalid alignment inputs") {
    void* p1 = kmalloc(0);
    TEST_ASSERT(p1 == NULL);

    void* p2 = aligned_kalloc(33, 64);  // 33 is not power of 2
    TEST_ASSERT(p2 == NULL);

    void* p3 = aligned_kalloc(512, 16);
    TEST_ASSERT(p3 != NULL);
    TEST_ASSERT(is_aligned((uintptr_t)p3, 512));
    kfree(p3, 16);
}

TEST(heap_interleaved, "Heap: Interleaved alloc/free pattern") {
    void* p1 = kmalloc(64);
    void* p2 = kmalloc(64);
    void* p3 = kmalloc(128);

    TEST_ASSERT(p1 && p2 && p3);

    kfree(p2, 64);

    void* p4 = kmalloc(64);

    TEST_ASSERT(p4 != NULL);

    kfree(p1, 64);
    kfree(p3, 128);
    kfree(p4, 64);
}

TEST(heap_partial_block_logic, "Heap: Trigger partial block logic") {
    const int count = 300;
    const size_t sz = 8192;
    size_t size     = align_up(count * sizeof(void*), PAGE_SIZE_SMALL);
    void** ptrs = (void**)vmm_alloc(&kernel_space, size, VMM_FLAG_READ | VMM_FLAG_WRITE, 1, 0x1000);

    TEST_ASSERT(ptrs != NULL);

    for (int i = 0; i < count; i++) {
        ptrs[i] = kmalloc(sz);
        TEST_ASSERT(ptrs[i] != NULL);

        *(volatile char*)ptrs[i] = 0;
    }

    for (int i = 0; i < count; i++) {
        kfree(ptrs[i], sz);
    }

    vmm_free(&kernel_space, (void*)ptrs, size);
}

#endif