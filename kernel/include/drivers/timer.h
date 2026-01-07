#ifndef KERNEL_DRIVERS_TIMER_H
#define KERNEL_DRIVERS_TIMER_H 1

#include <stddef.h>
#include <stdint.h>

#include "drivers/arch_timer.h"

#ifdef __cplusplus
extern "C" {
#endif

void timer_set_clock_source(clock_source_t source);
void timer_mdelay(size_t ms);
void timer_udelay(size_t us);
void timer_init(void);

#ifdef __cplusplus
}
#endif

#endif