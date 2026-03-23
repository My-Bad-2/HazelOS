#ifndef KERNEL_DRIVERS_PIT_H
#define KERNEL_DRIVERS_PIT_H 1

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

void pit_init(void);
void pit_disable(void);

uint64_t pit_get_ticks(void);
uint64_t pit_get_hz(void);
uint64_t pit_get_time_ms(void);
uint64_t pit_get_time_us(void);
uint64_t pit_get_time_ns(void);

void pit_tick(void);
void pit_mdelay(uint64_t ms);
void pit_udelay(uint64_t us);

#ifdef __cplusplus
}
#endif

#endif