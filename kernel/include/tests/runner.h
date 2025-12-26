#ifndef KERNEL_TESTS_RUNNER_H
#define KERNEL_TESTS_RUNNER_H 1

#ifdef __cplusplus
extern "C" {
#endif

#if KERNEL_TEST

typedef void (*test_func_t)(void);

typedef struct test_case {
    const char* name;
    test_func_t function;
} test_case_t;

#define TEST(test_name, description)                \
    void test_name##_func(void);                    \
    [[gnu::section(".tests"), gnu::used]]           \
    static const test_case_t test_name##_struct = { \
        .name     = (description),                  \
        .function = test_name##_func,               \
    };                                              \
    void test_name##_func(void)

#define TEST_ASSERT(cond)                                        \
    if (!(cond)) {                                               \
        kernel_test_report_fail(#cond, __FILE_NAME__, __LINE__); \
        return;                                                  \
    }

void kernel_test_report_fail(const char* expr, const char* file, int line);
void kernel_run_tests(void);

#else

#define TEST(x, d)
#define TEST_ASSERT(x)

#endif

#ifdef __cplusplus
}
#endif

#endif