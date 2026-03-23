#include "drivers/tsc.h"

#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>

#include "arch.h"
#include "boot/boot.h"
#include "cpu/cpu.h"
#include "cpu/registers.h"
#include "drivers/timer.h"
#include "libs/log.h"
#include "libs/math.h"

static uint64_t tsc_freq_hz   = 0;
static uint64_t tsc_boot_time = 0;
static bool warned_no_tsc     = false;
static bool warned_no_freq    = false;

bool tsc_is_invarient(void) {
    return cpu_has_feature(FEATURE_TSC_INVARIANT);
}

void tsc_init(void) {
    if (tsc_freq_hz != 0) {
        KLOG_DEBUG("TSC: already initialized freq=%lu Hz\n", tsc_freq_hz);
        return;
    }

    if (!tsc_is_invarient()) {
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
    uint64_t diff    = end_tsc - start_tsc;

    // Frequency = (Ticks / Time (in sec))
    tsc_freq_hz   = (diff * 1000) / calibaration_ms;
    tsc_boot_time = end_tsc;

    timer_set_clock_source(CLOCK_TSC);

    KLOG_INFO("TSC: calibrated freq=%lu Hz over %lu ms\n", tsc_freq_hz, calibaration_ms);
}

void tsc_ndelay(uint64_t ns) {
    if (tsc_freq_hz == 0) {
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

void tsc_udelay(uint64_t us) {
    tsc_ndelay(us * 1000ul);
}

void tsc_mdelay(uint64_t ms) {
    tsc_ndelay(ms * 1000000ul);
}

uint64_t tsc_get_uptime_ns(void) {
    if (tsc_freq_hz == 0) {
        if (!warned_no_tsc) {
            warned_no_tsc = true;
            KLOG_WARN("TSC: get time requested before calibration\n");
        }

        return 0;
    }

    uint64_t current_tsc = tsc_read();
    if (current_tsc < tsc_boot_time) {
        return 0;
    }

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

static _Atomic(uint32_t) cores_arrived = 0;
static _Atomic(uint32_t) bsp_go_signal = 0;
static uint64_t target_tsc_val         = 0;

// BTW Not worth it
void tsc_sync_bsp(void) {
    while ((atomic_load_explicit(&cores_arrived, memory_order_seq_cst) + 1) <
           mp_request.response->cpu_count) {
        arch_pause();
    }

    // Read the BSP's current TSC and add a small buffer for memory latency.
    // Setting it slightly in the future ensures that by the time the APs read this variable from
    // RAM/L3 cache, the time is perfectly aligned.
    target_tsc_val = tsc_read() + 50000;

    atomic_store_explicit(&bsp_go_signal, 1, memory_order_seq_cst);
    write_msr(X86_MSR_IA32_TSC, target_tsc_val);
}

void tsc_sync_ap(void) {
    atomic_fetch_add_explicit(&cores_arrived, 1, memory_order_seq_cst);

    while (atomic_load_explicit(&bsp_go_signal, memory_order_seq_cst) == 0) {
        arch_pause();
    }

    write_msr(X86_MSR_IA32_TSC, target_tsc_val);
}