#ifndef KERNEL_DRIVERS_HPET_H
#define KERNEL_DRIVERS_HPET_H 1

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

void hpet_init(void);
void hpet_disable(void);

void hpet_mdelay(uint64_t ms);
void hpet_udelay(uint64_t us);
void hpet_ndelay(uint64_t ns);

uint64_t hpet_get_hz(void);
uint64_t hpet_get_ticks(void);

uint64_t hpet_get_time_ns(void);
uint64_t hpet_get_time_us(void);
uint64_t hpet_get_time_ms(void);

#ifdef __cplusplus
}
#endif

#endif