#include "drivers/timer.h"

#include <errno.h>
#include <stdbool.h>

#include "cpu/exception.h"
#include "drivers/arch_timer.h"
#include "drivers/hpet.h"
#include "drivers/pit.h"
#include "libs/log.h"

static clock_source_t source;

static const char* timer_clock_source_name(clock_source_t src) {
    switch (src) {
        case CLOCK_PIT:
            return "PIT";
        case CLOCK_HPET:
            return "HPET";
        default:
            return "UNKNOWN";
    }
}

static void timer_handler(interrupt_trapframe_t*, void*) {
    static bool warned;

    switch (source) {
        case CLOCK_PIT:
            pit_tick();
            break;
        case CLOCK_HPET:
            break;
        default:
            if (!warned) {
                warned = true;
                errno  = EINVAL;
                KLOG_WARN("TIMER: IRQ received with invalid clock source=%d\n", source);
            }
            break;
    }
}

void timer_set_clock_source(clock_source_t src) {
    source = src;
    KLOG_INFO("TIMER: clock source set to %s\n", timer_clock_source_name(src));
}

void timer_mdelay(size_t ms) {
    switch (source) {
        case CLOCK_PIT:
            pit_mdelay(ms);
            break;
        case CLOCK_HPET:
            hpet_mdelay(ms);
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
        default:
            errno = ENODEV;
            KLOG_WARN("TIMER: udelay requested before clock source was initialized\n");
            break;
    }
}

void timer_init(void) {
    pit_init();
    hpet_init();

    KLOG_INFO("TIMER: active source=%s\n", timer_clock_source_name(source));

    register_external_irq_handler(
        IRQ_TIMER,
        timer_handler,
        nullptr,
        DELIVERY_MODE_LOWEST_PRIO,
        DESTMODE_PHYSICAL,
        0
    );
}