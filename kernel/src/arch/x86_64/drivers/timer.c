#include "drivers/timer.h"

#include <stdbool.h>

#include "arch.h"
#include "boot/boot.h"
#include "cpu/cpu.h"
#include "cpu/exception.h"
#include "cpu/lapic.h"
#include "cpu/smp.h"
#include "drivers/tsc.h"
#include "libs/log.h"
#include "libs/math.h"

static uint64_t tsc_freq_hz   = 0;
static uint64_t tsc_boot_time = 0;

static irq_return_t timer_handler(interrupt_trapframe_t*, void*) {
    timer_manager_tick(smp_current_core()->timer_manager);
    return IRQ_HANDLED;
}

static bool tsc_is_invarient(void) {
    return cpu_has_feature(FEATURE_TSC_INVARIANT);
}

void timer_ndelay(uint64_t ns) {
    if (tsc_freq_hz == 0) return;

    // 1000000000 = 10^9 (1 Billion)
    uint64_t target_ticks = muldiv64(ns, tsc_freq_hz, 1000000000ul);
    uint64_t start        = tsc_read();

    while ((tsc_read() - start) < (target_ticks)) arch_pause();
}

uint64_t timer_get_time(void) {
    if (tsc_freq_hz == 0) return 0;

    uint64_t current_tsc = tsc_read();
    if (current_tsc < tsc_boot_time) return 0;

    uint64_t elapsed_ticks = current_tsc - tsc_boot_time;
    // Formula: (elapsed_ticks * 1,000,000,000) / tsc_frequency
    return muldiv64(elapsed_ticks, 1000000000ul, tsc_freq_hz);
}

void timer_init(void) {
    if (tsc_freq_hz != 0) return;
    KLOG_INIT_START("TSC");

    if (!tsc_is_invarient()) {
        KLOG_INIT_FAIL();
        return;
    }

    tsc_freq_hz   = tsc_frequency_request.response->frequency;
    tsc_boot_time = tsc_read();
    KLOG_INIT_OK();

    lapic_timer_calibrate();

    irq_config_t config = {
        .delivery  = DELIVERY_MODE_LOWEST_PRIO,
        .dest      = DESTMODE_PHYSICAL,
        .dest_apic = 0
    };

    int res = register_irq(IRQ_TIMER, timer_handler, nullptr, &config);
    if (res != 0) KLOG_ERROR("TIMER: failed to register timer_handler!\n");
}