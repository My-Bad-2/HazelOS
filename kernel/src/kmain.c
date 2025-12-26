#include "arch.h"
#include "libs/log.h"

void kmain() {
    arch_serial_init();

    KLOG_INFO("Hello, World!\n");

    arch_halt(true);
}