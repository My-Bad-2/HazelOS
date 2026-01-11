#ifndef KERNEL_DRIVERS_TSC_H
#define KERNEL_DRIVERS_TSC_H 1

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

void tsc_init(void);
bool tsc_is_invarient(void);

void tsc_mdelay(size_t ms);
void tsc_udelay(size_t us);
void tsc_ndelay(size_t ns);

size_t tsc_get_time(void);
size_t tsc_get_hz(void);

#ifdef __cplusplus
}
#endif

#endif