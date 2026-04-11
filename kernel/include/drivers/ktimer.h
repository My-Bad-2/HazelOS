#ifndef KERNEL_DRIVERS_KTIMER_H
#define KERNEL_DRIVERS_KTIMER_H 1

#include <stdint.h>

#include "drivers/timer.h"
#include "sched/ipc.h"

#include "internal/hr_timer.h"
#include "internal/lr_timer.h"

#define HRTIMER_THRESHOLD_NS (NS_PER_SEC / MS_PER_SEC)

typedef enum {
    KTIMER_STATE_UNARMED = 0,
    KTIMER_STATE_LR,
    KTIMER_STATE_HR,
} ktimer_state_t;

struct kernel_timer {
    struct kobject refcount;
    qspinlock_t lock;

    struct ipc_port* bound_port;
    struct ipc_port_object port_state;

    ktimer_state_t state;
    union {
        struct lrtimer_event lr;
        struct hrtimer_event hr;
    } event;
};

void ktimer_init(void);
void ktimer_release(struct kobject* ref);

int sys_timer_create(uint64_t* cap_out);
int sys_timer_set(uint64_t timer_cap, uint64_t delay_ns, uint64_t interval_ns);
int sys_timer_cancel(uint64_t timer_cap);

#endif