#include "tests/runner.h"

#include "libs/log.h"

#if KERNEL_TEST

extern const test_case_t __start_tests[];
extern const test_case_t __stop_tests[];

static bool current_test_failed = false;

void kernel_test_report_fail(const char* expr, const char* file, int line) {
    current_test_failed = true;
    KLOG_ERROR("Assertion failed: (%s) in %s:%d\n", expr, file, line);
}

void kernel_run_tests(void) {
    const test_case_t* start = __start_tests;
    const test_case_t* end   = __stop_tests;

    int total_count  = 0;
    int passed_count = 0;
    int failed_count = 0;

    KLOG_INFO("========================================\n");
    KLOG_INFO("       STARTING KERNEL UNIT TESTS       \n");
    KLOG_INFO("========================================\n");

    // Iterate over the memory section directly
    for (const test_case_t* t = start; t < end; ++t) {
        total_count++;
        current_test_failed = false;

        KLOG_DEBUG("Running test: %s\n", t->name);

        t->function();

        if (current_test_failed) {
            failed_count++;
            KLOG_WARN("Test FAILED: %s\n", t->name);
        } else {
            passed_count++;
            KLOG_INFO("Test PASSED: %s\n", t->name);
        }
    }

    KLOG_INFO("========================================\n");
    KLOG_INFO("TEST SUMMARY\n");
    KLOG_INFO("Total:  %d\n", total_count);
    KLOG_INFO("Passed: %d\n", passed_count);

    if (failed_count > 0) {
        KLOG_ERROR("Failed: %d\n", failed_count);
        KLOG_WARN("SOME TESTS FAILED\n");
    } else {
        KLOG_INFO("Failed: 0\n");
        KLOG_INFO("ALL TESTS PASSED\n");
    }
    KLOG_INFO("========================================\n");
}

#endif