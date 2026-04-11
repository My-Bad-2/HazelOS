#ifndef KERNEL_DRIVERS_TIMER_H
#define KERNEL_DRIVERS_TIMER_H 1

#include <stddef.h>
#include <stdint.h>

#include "drivers/arch_timer.h"

#ifdef __cplusplus
extern "C" {
#endif

#define NS_PER_SEC 1000000000ul
#define US_PER_SEC 1000000ul
#define MS_PER_SEC 1000ul

void timer_ndelay(size_t ns);

static inline void timer_udelay(size_t us) {
    timer_ndelay(us * (NS_PER_SEC / US_PER_SEC));
}

static inline void timer_mdelay(size_t ms) {
    timer_ndelay(ms * (NS_PER_SEC / MS_PER_SEC));
}

void timer_configure(timer_mode_t mode, uint8_t vector);
void timer_start_ms(uint64_t ms);
void timer_start_us(uint64_t us);
void timer_start_ns(uint64_t ns);

size_t timer_get_time(void);

static inline uint64_t timer_get_time_us(void) {
    return timer_get_time() / (NS_PER_SEC / US_PER_SEC);
}

static inline uint64_t timer_get_time_ms(void) {
    return timer_get_time() / (NS_PER_SEC / MS_PER_SEC);
}

void timer_init(void);

#ifdef __cplusplus
}
#endif

#endif