#include "arch.h"
#include "cpu/smp.h"
#include "drivers/drivers.h"
#include "drivers/loader.h"
#include "libs/log.h"
#include "memory/memory.h"
#include "sched/scheduler.h"
#include "tests/runner.h"

// NOLINTNEXTLINE(misc-use-internal-linkage)
void kmain(void) {
    arch_serial_init();

    memory_init();
    smp_init();

    drivers_init();
    scheduler_init();

#if KERNEL_TEST
    // Enable when we've introduced new tests
    const bool run_tests = false;

    if (run_tests) {
        kernel_run_tests();
    }
#endif

    KLOG_INFO("Hello, World!\n");
    // launch_user_init();

    arch_halt(true);
}