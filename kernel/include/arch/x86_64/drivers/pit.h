#ifndef KERNEL_DRIVERS_PIT_H
#define KERNEL_DRIVERS_PIT_H 1

#include <stddef.h>
#include <stdint.h>

#include "drivers/arch_timer.h"

#ifdef __cplusplus
extern "C" {
#endif

void pit_init(void);
void pit_disable(void);

uint64_t pit_get_ticks(void);

void pit_tick(void);

void pit_mdelay(size_t ms);
void pit_udelay(size_t us);

void pit_configure_timer(timer_type_t type, uint32_t freq_hz);

#ifdef __cplusplus
}
#endif

#endif