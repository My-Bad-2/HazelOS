#include "memory/vma.h"

#include "memory/memory.h"
#include "memory/pagemap.h"
#include "memory/vmm.h"
#include "tests/runner.h"

#if KERNEL_TEST

static vm_space_t test_space;
static void vmm_test_setup(void) {
    vmm_init_space(&test_space, vmm_get_kernel_pagemap(), 0x10000, 0x10000000);
}

TEST(vmm_basic_alloc, "VMM: Basic Allocation & Alignment Checks") {
    vmm_test_setup();

    void* ptr1 = vmm_alloc(
        &test_space,
        4096,
        VMM_FLAG_READ | VMM_FLAG_WRITE,
        CACHE_WRITE_BACK,
        PAGE_SIZE_SMALL
    );

    TEST_ASSERT(ptr1 != nullptr);
    TEST_ASSERT((uintptr_t)ptr1 == 0x10000);

    vm_area_t* vma = vmm_find_vma(&test_space, (uintptr_t)ptr1);
    TEST_ASSERT(vma != nullptr);
    TEST_ASSERT(vma->size == 4096);
    TEST_ASSERT(vma->flags & VMM_FLAG_READ | VMM_FLAG_WRITE);

    void* ptr2 = vmm_alloc(
        &test_space,
        PAGE_SIZE_MEDIUM,
        VMM_FLAG_READ | VMM_FLAG_WRITE,
        CACHE_WRITE_BACK,
        PAGE_SIZE_MEDIUM
    );

    TEST_ASSERT(ptr2 != nullptr);
    TEST_ASSERT((uintptr_t)ptr2 == 0x200000);

    TEST_ASSERT(vmm_find_vma(&test_space, 0x11000) == nullptr);

    vmm_free(&test_space, ptr1);
    vmm_free(&test_space, ptr2);
}

TEST(vmm_gap_fill, "VMM: Gap Search (Best Fit / First Fit)") {
    vmm_test_setup();

    void* p1 = vmm_alloc(
        &test_space,
        0x1000,
        VMM_FLAG_READ | VMM_FLAG_WRITE,
        CACHE_WRITE_BACK,
        PAGE_SIZE_SMALL
    );

    void* p2 = vmm_alloc(
        &test_space,
        0x1000,
        VMM_FLAG_READ | VMM_FLAG_WRITE,
        CACHE_WRITE_BACK,
        PAGE_SIZE_SMALL
    );

    void* p3 = vmm_alloc(
        &test_space,
        0x1000,
        VMM_FLAG_READ | VMM_FLAG_WRITE,
        CACHE_WRITE_BACK,
        PAGE_SIZE_SMALL
    );

    TEST_ASSERT((uintptr_t)p1 == 0x10000);
    TEST_ASSERT((uintptr_t)p2 == 0x11000);
    TEST_ASSERT((uintptr_t)p3 == 0x12000);

    vmm_free(&test_space, p2);
    TEST_ASSERT(vmm_find_vma(&test_space, 0x11000) == nullptr);

    test_space.alloc_hint = test_space.start_limit;

    void* p_new = vmm_alloc(&test_space, 0x1000, VMM_FLAG_READ, CACHE_WRITE_BACK, PAGE_SIZE_SMALL);
    TEST_ASSERT((uintptr_t)p_new == 0x11000);
}

TEST(vmm_demand_vs_immediate, "VMM: Demand Paging Flag Behavior") {
    vmm_test_setup();

    void* p1 = vmm_alloc(&test_space, 0x1000, VMM_FLAG_DEMAND, CACHE_WRITE_BACK, PAGE_SIZE_SMALL);
    TEST_ASSERT(p1 != nullptr);

    void* p2 = vmm_alloc(&test_space, 0x1000, VMM_FLAG_READ, CACHE_WRITE_BACK, PAGE_SIZE_SMALL);
    TEST_ASSERT(p2 != nullptr);
}

TEST(vmm_cow_setup, "VMM: Zero Page COW Logic Check") {
    vmm_test_setup();

    void* ptr = vmm_alloc(&test_space, 0x1000, VMM_FLAG_PRIVATE, CACHE_WRITE_BACK, PAGE_SIZE_SMALL);

    TEST_ASSERT(ptr != nullptr);
}

TEST(vmm_free_logic, "VMM: Freeing Resources") {
    vmm_test_setup();

    void* ptr = vmm_alloc(&test_space, 0x2000, VMM_FLAG_READ, CACHE_WRITE_BACK, PAGE_SIZE_SMALL);
    TEST_ASSERT(ptr != nullptr);

    vmm_free(&test_space, ptr);

    TEST_ASSERT(vmm_find_vma(&test_space, (uintptr_t)ptr) == nullptr);
}

#endif