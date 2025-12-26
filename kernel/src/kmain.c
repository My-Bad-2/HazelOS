#include "arch.h"
#include "libs/log.h"
#include "memory/memory.h"
#include "tests/runner.h"

void kmain() {
    arch_serial_init();

    memory_init();
    kernel_run_tests();
    KLOG_INFO("Hello, World!\n");

    arch_halt(true);
}