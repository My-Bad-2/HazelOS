#include "arch.h"
#include "libs/log.h"
#include "memory/memory.h"

void kmain() {
    arch_serial_init();

    memory_init();
    KLOG_INFO("Hello, World!\n");

    arch_halt(true);
}