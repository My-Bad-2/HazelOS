#include "drivers/pit.h"

#include <errno.h>
#include <stdatomic.h>
#include <stdint.h>

#include "arch.h"
#include "cpu/io.h"
#include "drivers/arch_timer.h"
#include "drivers/timer.h"
#include "libs/log.h"
#include "libs/spinlock.h"

#include "internal/pit.h"

static atomic_size_t global_ticks    = 0;
static atomic_uint current_frequency = 0;
static bool warned_zero_freq         = false;

static void set_pit_frequency(uint32_t freq) {
    if (freq == 0) {
        errno = EINVAL;
        KLOG_WARN("PIT: requested zero frequency, defaulting to 1000 Hz\n");
        freq = 1000;
    }

    uint32_t divisor = PIT_BASE_FREQ / freq;

    if (divisor == 0 || divisor > UINT16_MAX) {
        errno = EINVAL;
        KLOG_WARN("PIT: invalid divisor for freq=%u Hz\n", freq);
        return;
    }

    atomic_store_explicit(&current_frequency, freq, memory_order_seq_cst);

    uint8_t cmd = PIT_SELECT_CH0 | PIT_ACCESS_LOHI | PIT_MODE_3;
    io_write8(PIT_PORT_CMD, cmd);
    io_wait();

    io_write8(PIT_PORT_CH0, (uint8_t)(divisor & 0xff));
    io_wait();
    io_write8(PIT_PORT_CH0, (uint8_t)((divisor >> 8) & 0xff));

    KLOG_DEBUG("PIT: frequency set to %u Hz (div=%u)\n", freq, divisor);
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

size_t pit_get_hz(void) {
    return current_frequency;
}

void pit_disable(void) {
    uint8_t cmd = PIT_ACCESS_LOHI | PIT_MODE_0;
    io_write8(PIT_PORT_CMD, cmd);
    io_wait();

    io_write8(PIT_PORT_CH0, 2);
    io_wait();
    io_write8(PIT_PORT_CH0, 0);
    io_wait();
}

void pit_init(void) {
    const uint32_t freq = 1000;
    set_pit_frequency(freq);
    timer_set_clock_source(CLOCK_PIT);
    KLOG_INFO("PIT: initialized at %u Hz\n", freq);
}

void pit_mdelay(size_t ms) {
    size_t start_ticks = pit_get_ticks();

    uint32_t freq = atomic_load_explicit(&current_frequency, memory_order_seq_cst);

    if (freq == 0) {
        errno = ENODEV;

        if (!warned_zero_freq) {
            warned_zero_freq = true;
            KLOG_WARN("PIT: mdelay requested while frequency is zero\n");
        }

        return;
    }

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