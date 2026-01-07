#include "drivers/pit.h"

#include <stdatomic.h>
#include <stdint.h>

#include "arch.h"
#include "cpu/io.h"
#include "drivers/arch_timer.h"
#include "drivers/timer.h"
#include "libs/spinlock.h"

#include "internal/pit.h"

static atomic_size_t global_ticks    = 0;
static atomic_uint current_frequency = 0;

static void set_pit_frequency(uint32_t freq) {
    if (freq == 0) {
        freq = 1000;
    }

    uint32_t divisor = PIT_BASE_FREQ / freq;

    if (divisor > UINT16_MAX) {
        divisor = 0;
    }

    atomic_store_explicit(&current_frequency, freq, memory_order_seq_cst);

    uint8_t cmd = PIT_SELECT_CH0 | PIT_ACCESS_LOHI | PIT_MODE_3;
    io_write8(PIT_PORT_CMD, cmd);
    io_wait();

    io_write8(PIT_PORT_CH0, (uint8_t)(divisor & 0xff));
    io_wait();
    io_write8(PIT_PORT_CH0, (uint8_t)((divisor >> 8) & 0xff));
}

static uint16_t pit_read_hardware_count(void) {
    uint16_t count = 0;
    irq_lock_t lock;

    acquire_irq_lock(&lock);

    uint8_t cmd = PIT_SELECT_CH0 | PIT_ACCESS_LATCH;

    io_write8(PIT_PORT_CMD, cmd);
    io_wait();

    count = io_read8(PIT_PORT_CH0);
    count |= io_read8(PIT_PORT_CH0) << 8;

    release_irq_lock(&lock);
    return count;
}

void pit_tick(void) {
    atomic_fetch_add_explicit(&global_ticks, 1, memory_order_seq_cst);
}

uint64_t pit_get_ticks(void) {
    return atomic_load_explicit(&global_ticks, memory_order_seq_cst);
}

void pit_init(void) {
    const uint32_t freq = 1000;
    set_pit_frequency(freq);
    timer_set_clock_source(CLOCK_PIT);
}

void pit_mdelay(size_t ms) {
    size_t start_ticks = pit_get_ticks();

    uint32_t freq          = atomic_load_explicit(&current_frequency, memory_order_seq_cst);
    uint64_t ticks_to_wait = (ms * freq) / 1000;
    uint64_t target        = start_ticks + ticks_to_wait;

    while (pit_get_ticks() < target) {
        arch_pause();
    }
}

void pit_udelay(size_t us) {
    if (us >= 1000) {
        pit_mdelay(us / 1000);
        us %= 1000;

        if (us == 0) {
            return;
        }
    }

    uint32_t ticks_needed = (uint32_t)((us * 1193) / 1000);
    uint16_t start_count  = pit_read_hardware_count();

    while (true) {
        uint16_t curr_count = pit_read_hardware_count();
        uint16_t elapsed    = 0;

        if (start_count >= curr_count) {
            elapsed = start_count - curr_count;
        } else {
            elapsed = start_count + (UINT16_MAX - curr_count);
        }

        if (elapsed >= ticks_needed) {
            break;
        }
    }
}

void pit_configure_timer(timer_type_t type, uint32_t freq_hz) {
    if (freq_hz == 0) {
        freq_hz = 1000;
    }

    if (freq_hz > PIT_BASE_FREQ) {
        freq_hz = PIT_BASE_FREQ;
    }

    uint32_t divisor = PIT_BASE_FREQ / freq_hz;

    if (divisor > UINT16_MAX) {
        divisor = 0;
    }

    atomic_store_explicit(&current_frequency, freq_hz, memory_order_seq_cst);

    uint8_t cmd = 0;

    if (type == TIMER_ONESHOT) {
        cmd = PIT_SELECT_CH0 | PIT_ACCESS_LOHI | PIT_MODE_0 | PIT_VAL_16BIT;
    } else {
        cmd = PIT_SELECT_CH0 | PIT_ACCESS_LOHI | PIT_MODE_2 | PIT_VAL_16BIT;
    }

    irq_lock_t lock;

    acquire_irq_lock(&lock);

    io_write8(PIT_PORT_CMD, cmd);
    io_wait();

    io_write8(PIT_PORT_CH0, divisor & 0xff);
    io_wait();
    io_write8(PIT_PORT_CH0, (divisor >> 8) & 0xff);

    release_irq_lock(&lock);
}