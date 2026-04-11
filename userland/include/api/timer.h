#ifndef USERLAND_API_TIMER_H
#define USERLAND_API_TIMER_H 1

#include <stdint.h>

#define SYS_CATEGORY_TIMER 0x0500

#define SYS_TIMER_CREATE (SYS_CATEGORY_TIMER | 0x01)
#define SYS_TIMER_CANCEL (SYS_CATEGORY_TIMER | 0x02)
#define SYS_TIMER_SET    (SYS_CATEGORY_TIMER | 0x03)

#define NS_PER_SEC 1000000000ul
#define US_PER_SEC 1000000ul
#define MS_PER_SEC 1000ul

int timer_create(uint64_t* cap_out);
int timer_set(uint64_t timer_cap, uint64_t delay_ns, uint64_t interval_ns);
int timer_cancel(uint64_t timer_cap);

static inline int timer_set_periodic(uint64_t timer_cap, uint64_t interval_ns) {
    return timer_set(timer_cap, 0, interval_ns);
}

static inline int timer_set_oneshot(uint64_t timer_cap, uint64_t delay_ns) {
    return timer_set(timer_cap, delay_ns, 0);
}

#endif