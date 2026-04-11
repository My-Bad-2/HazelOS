#include "drivers/timer.h"

#include <stdbool.h>

#include "cpu/exception.h"
#include "cpu/lapic.h"
#include "cpu/smp.h"
#include "drivers/tsc.h"
#include "libs/log.h"

static bool warned_invalid_mode   = false;
static bool warned_invalid_source = false;

static irq_return_t timer_handler(interrupt_trapframe_t*, void*) {
    per_cpu_data_t* cpu = smp_current_core();

    timer_manager_tick(cpu->timer_manager);

    return IRQ_HANDLED;
}

void timer_mdelay(size_t ms) {
    tsc_mdelay(ms);
}

void timer_udelay(size_t us) {
    tsc_udelay(us);
}

size_t timer_get_time(void) {
    return tsc_get_uptime_ns();
}

size_t timer_get_time_ms(void) {
    return tsc_get_uptime_ms();
}

size_t timer_get_hz(void) {
    return tsc_get_hz();
}

void timer_init(void) {
    tsc_init();

    lapic_timer_calibrate();

    irq_config_t config = {
        .delivery  = DELIVERY_MODE_LOWEST_PRIO,
        .dest      = DESTMODE_PHYSICAL,
        .dest_apic = 0
    };

    int res = register_irq(IRQ_TIMER, timer_handler, nullptr, &config);
    if (res != 0) KLOG_ERROR("TIMER: failed to register timer_handler!\n");
}