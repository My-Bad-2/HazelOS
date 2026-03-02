#include "arch.h"
#include "cpu/smp.h"
#include "drivers/drivers.h"
#include "drivers/loader.h"
#include "libs/log.h"
#include "memory/memory.h"
#include "sched/rcu.h"
#include "sched/scheduler.h"

// NOLINTNEXTLINE(misc-use-internal-linkage)
void kmain(void) {
    arch_serial_init();
    drivers_early_init();

    memory_init();
    smp_init();

    drivers_init();
    scheduler_init();

    KLOG_INFO("Hello, World!\n");
    launch_user_init();

    arch_halt(true);
}