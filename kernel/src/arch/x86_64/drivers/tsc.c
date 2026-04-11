#include "drivers/tsc.h"

#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>

#include "arch.h"
#include "boot/boot.h"
#include "cpu/cpu.h"
#include "libs/log.h"
#include "libs/math.h"

static uint64_t tsc_freq_hz   = 0;
static uint64_t tsc_boot_time = 0;

bool tsc_is_invarient(void) {
    return cpu_has_feature(FEATURE_TSC_INVARIANT);
}

void tsc_init(void) {
    if (tsc_freq_hz != 0) return;
    KLOG_INIT_START("TSC");

    if (!tsc_is_invarient()) {
        KLOG_INIT_FAIL();
        return;
    }

    tsc_freq_hz   = tsc_frequency_request.response->frequency;
    tsc_boot_time = tsc_read();
    KLOG_INIT_OK();
}

void tsc_ndelay(uint64_t ns) {
    if (tsc_freq_hz == 0) return;

    // 1000000000 = 10^9 (1 Billion)
    uint64_t target_ticks = muldiv64(ns, tsc_freq_hz, 1000000000ul);
    uint64_t start        = tsc_read();

    while ((tsc_read() - start) < (target_ticks)) arch_pause();
}

void tsc_udelay(uint64_t us) {
    tsc_ndelay(us * 1000ul);
}

void tsc_mdelay(uint64_t ms) {
    tsc_ndelay(ms * 1000000ul);
}

uint64_t tsc_get_uptime_ns(void) {
    if (tsc_freq_hz == 0) return 0;

    uint64_t current_tsc = tsc_read();
    if (current_tsc < tsc_boot_time) return 0;

    uint64_t elapsed_ticks = current_tsc - tsc_boot_time;
    // Formula: (elapsed_ticks * 1,000,000,000) / tsc_frequency
    return muldiv64(elapsed_ticks, 1000000000ul, tsc_freq_hz);
}

uint64_t tsc_get_uptime_us(void) {
    return tsc_get_uptime_ns() / 1000ul;
}

uint64_t tsc_get_uptime_ms(void) {
    return tsc_get_uptime_ns() / 1000000ul;
}

uint64_t tsc_get_hz(void) {
    return tsc_freq_hz;
}