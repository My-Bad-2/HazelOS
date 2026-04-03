#include "drivers/timer.h"

#include <errno.h>
#include <stdbool.h>

#include "cpu/exception.h"
#include "cpu/lapic.h"
#include "cpu/smp.h"
#include "drivers/arch_timer.h"
#include "drivers/hpet.h"
#include "drivers/pit.h"
#include "drivers/tsc.h"
#include "libs/log.h"

static clock_source_t source = CLOCK_PIT;

static bool warned_invalid_mode   = false;
static bool warned_invalid_source = false;

static const char* timer_clock_source_name(clock_source_t src) {
    switch (src) {
        case CLOCK_PIT:
            return "PIT";
        case CLOCK_HPET:
            return "HPET";
        case CLOCK_TSC:
            return "TSC";
        default:
            return "UNKNOWN";
    }
}

static irq_return_t timer_handler(interrupt_trapframe_t*, void*) {
    per_cpu_data_t* cpu = smp_current_core();

    timer_tick();
    timer_manager_tick(cpu->timer_manager);

    return IRQ_HANDLED;
}

void timer_tick(void) {
    static bool warned;

    switch (source) {
        case CLOCK_PIT:
            pit_tick();
            break;
        case CLOCK_HPET:
        case CLOCK_TSC:
            break;
        default:
            if (!warned) {
                warned = true;
                KLOG_WARN("TIMER: IRQ received with invalid clock source=%d\n", source);
            }
            break;
    }
}

void timer_set_clock_source(clock_source_t src) {
    switch (src) {
        case CLOCK_PIT:
        case CLOCK_HPET:
        case CLOCK_TSC:
            source = src;
            break;
        default:
            if (!warned_invalid_source) {
                warned_invalid_source = true;
                KLOG_WARN("TIMER: invalid clock source requested=%d\n", src);
            }
            break;
    }
}

void timer_mdelay(size_t ms) {
    switch (source) {
        case CLOCK_PIT:
            pit_mdelay(ms);
            break;
        case CLOCK_HPET:
            hpet_mdelay(ms);
            break;
        case CLOCK_TSC:
            tsc_mdelay(ms);
            break;
        default:
            errno = ENODEV;
            KLOG_WARN("TIMER: mdelay requested before clock source was initialized\n");
            break;
    }
}

void timer_udelay(size_t us) {
    switch (source) {
        case CLOCK_PIT:
            pit_udelay(us);
            break;
        case CLOCK_HPET:
            hpet_udelay(us);
            break;
        case CLOCK_TSC:
            tsc_udelay(us);
            break;
        default:
            KLOG_WARN("TIMER: udelay requested before clock source was initialized\n");
            break;
    }
}

size_t timer_get_time(void) {
    switch (source) {
        case CLOCK_PIT:
            return pit_get_time_ns();
        case CLOCK_HPET:
            return hpet_get_time_ns();
        case CLOCK_TSC:
            return tsc_get_uptime_ns();
        default:
            KLOG_WARN("TIMER: get time requested before clock source was initialized\n");
            return 0;
    }
}

size_t timer_get_time_ms(void) {
    switch (source) {
        case CLOCK_PIT:
            return pit_get_time_ms();
        case CLOCK_HPET:
            return hpet_get_time_ms();
        case CLOCK_TSC:
            return tsc_get_uptime_ms();
        default:
            KLOG_WARN("TIMER: get time requested before clock source was initialized\n");
            return 0;
    }
}

size_t timer_get_hz(void) {
    switch (source) {
        case CLOCK_PIT:
            return pit_get_hz();
        case CLOCK_HPET:
            return hpet_get_hz();
        case CLOCK_TSC:
            return tsc_get_hz();
        default:
            KLOG_WARN("TIMER: get hz requested before clock source was initialized\n");
            return 0;
    }
}

void timer_configure(timer_mode_t mode, uint8_t vector, size_t count) {
    switch (mode) {
        case TIMER_ONESHOT:
        case TIMER_PERIODIC:
        case TIMER_TSC_DEADLINE:
            break;
        default:
            errno = EINVAL;

            if (!warned_invalid_mode) {
                warned_invalid_mode = true;
                KLOG_WARN("TIMER: configure called with invalid mode=%d\n", mode);
            }

            return;
    }

    KLOG_DEBUG("TIMER: configuring mode=%d vector=%u count=%zu\n", mode, vector, count);

    lapic_configure_timer(mode, vector, count);
}

void timer_init(void) {
    pit_init();
    hpet_init();
    tsc_init();

    KLOG_INFO("TIMER: active source=%s\n", timer_clock_source_name(source));

    lapic_timer_calibrate();

    irq_config_t config = {
        .delivery  = DELIVERY_MODE_LOWEST_PRIO,
        .dest      = DESTMODE_PHYSICAL,
        .dest_apic = 0
    };

    int res = register_irq(IRQ_TIMER, timer_handler, nullptr, &config);
    if (res != 0) {
        KLOG_ERROR("TIMER: failed to register timer_handler!\n");
    }
}