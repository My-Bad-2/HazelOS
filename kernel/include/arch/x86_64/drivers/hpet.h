#ifndef KERNEL_DRIVERS_HPET_H
#define KERNEL_DRIVERS_HPET_H 1

#include <stddef.h>
#include <stdint.h>

#include "drivers/arch_timer.h"

#ifdef __cplusplus
extern "C" {
#endif

void hpet_init(void);
void hpet_disable(void);

void hpet_mdelay(size_t ms);
void hpet_udelay(size_t us);
void hpet_ndelay(size_t ns);

void hpet_configure_timer(timer_type_t type, uint32_t ms, uint32_t gsi);

#ifdef __cplusplus
}
#endif

#endif