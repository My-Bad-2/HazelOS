#include "drivers/tsc.h"

#include <errno.h>
#include <stdbool.h>
#include <stdint.h>

#include "arch.h"
#include "compiler.h"
#include "cpu/cpu.h"
#include "drivers/timer.h"
#include "libs/log.h"

static uint64_t tsc_freq_hz   = 0;
static uint64_t tsc_boot_time = 0;
static bool warned_no_tsc     = false;
static bool warned_no_freq    = false;

static inline size_t tsc_read(void) {
    uint32_t lo = 0;
    uint32_t hi = 0;

    asm volatile("lfence" ::: "memory");
    asm volatile("rdtsc" : "=a"(lo), "=d"(hi));
    return ((size_t)hi << 32) | lo;
}

bool tsc_is_invarient(void) {
    return cpu_has_feature(FEATURE_TSC_INVARIANT);
}

void tsc_init(void) {
    if (tsc_freq_hz != 0) {
        errno = EAGAIN;
        KLOG_DEBUG("TSC: already initialized freq=%lu Hz\n", tsc_freq_hz);
        return;
    }

    if (!tsc_is_invarient()) {
        errno = ENODEV;
        KLOG_WARN("TSC: invariant TSC not available, skipping calibration\n");
        return;
    }

    // Warm up
    tsc_read();
    timer_mdelay(1);

    const uint64_t calibaration_ms = 50;
    uint64_t start_tsc             = tsc_read();

    timer_mdelay(calibaration_ms);
    uint64_t end_tsc = tsc_read();

    uint64_t diff = end_tsc - start_tsc;

    // Frequency = (Ticks / Time (in sec))
    tsc_freq_hz = (diff * 1000) / calibaration_ms;

    tsc_boot_time = end_tsc;

    timer_set_clock_source(CLOCK_TSC);

    KLOG_INFO("TSC: calibrated freq=%lu Hz over %lu ms\n", tsc_freq_hz, calibaration_ms);
}

// Standard uint64 multiplication will result in an overflow in just under 7 seconds after boot (on
// a 3GHz processor), hence we use 128-bits to widen up the space.
static inline uint64_t muldiv64(uint64_t a, uint64_t b, uint64_t c) {
    uint128_t res = (uint128_t)a * b;
    return (uint64_t)(res / c);
}

void tsc_ndelay(size_t ns) {
    if (tsc_freq_hz == 0) {
        errno = ENODEV;

        if (!warned_no_tsc) {
            warned_no_tsc = true;
            KLOG_WARN("TSC: ndelay requested before calibration\n");
        }

        return;
    }

    // 1000000000 = 10^9 (1 Billion)
    uint64_t target_ticks = muldiv64(ns, tsc_freq_hz, 1000000000ul);
    uint64_t start        = tsc_read();

    while ((tsc_read() - start) < (target_ticks)) {
        arch_pause();
    }
}

void tsc_udelay(size_t us) {
    tsc_ndelay(us * 1000);
}

void tsc_mdelay(size_t ms) {
    tsc_ndelay(ms * 1000000);
}

size_t tsc_get_time(void) {
    if (tsc_freq_hz == 0) {
        if (!warned_no_tsc) {
            warned_no_tsc = true;
            KLOG_WARN("TSC: get time requested before calibration\n");
        }

        return 0;
    }

    size_t current_tsc = tsc_read();

    if (current_tsc < tsc_boot_time) {
        return 0;
    }

    size_t elapsed_ticks = current_tsc - tsc_boot_time;
    return muldiv64(elapsed_ticks, 1000000000ul, tsc_freq_hz);
}

size_t tsc_get_hz(void) {
    return tsc_freq_hz;
}