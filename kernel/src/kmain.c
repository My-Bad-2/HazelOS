#include "arch.h"
#include "cpu/smp.h"
#include "drivers/drivers.h"
#include "libs/log.h"
#include "memory/memory.h"
#include "tests/runner.h"

void kmain(void) {
    arch_serial_init();

    memory_init();
    smp_init();

    drivers_init();

#if KERNEL_TEST
    kernel_run_tests();
#endif
    KLOG_INFO("Hello, World!\n");

    arch_halt(true);
}