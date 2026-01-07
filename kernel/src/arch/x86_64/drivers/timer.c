#include "drivers/timer.h"

#include "cpu/exception.h"
#include "drivers/arch_timer.h"
#include "drivers/pit.h"

static clock_source_t source;

static void timer_handler(interrupt_trapframe_t*, void*) {
    switch (source) {
        case CLOCK_PIT:
            pit_tick();
    }
}

void timer_set_clock_source(clock_source_t src) {
    source = src;
}

void timer_mdelay(size_t ms) {
    switch (source) {
        case CLOCK_PIT:
            pit_mdelay(ms);
    }
}

void timer_udelay(size_t us) {
    switch (source) {
        case CLOCK_PIT:
            pit_udelay(us);
    }
}

void timer_init(void) {
    pit_init();

    register_external_irq_handler(
        IRQ_TIMER,
        timer_handler,
        nullptr,
        DELIVERY_MODE_LOWEST_PRIO,
        DESTMODE_PHYSICAL,
        0
    );
}