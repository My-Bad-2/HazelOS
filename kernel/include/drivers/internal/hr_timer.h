#ifndef KERNEL_DRIVERS_HR_TIMER_H
#define KERNEL_DRIVERS_HR_TIMER_H 1

#include <stddef.h>
#include <stdint.h>

#include "libs/rb_tree.h"
#include "libs/spinlock.h"

typedef void (*timer_callback_t)(void*);

struct hrtimer_manager {
    struct rb_root_cached root;

    _Atomic(uint64_t) next_expires_ns;
    _Atomic(size_t) active_timers;

    qspinlock_t lock;
};

struct hrtimer_event {
    struct rb_node node;

    uint64_t expires_ns;
    uint64_t interval_ns;

    timer_callback_t callback;
    void* ctx;

    struct hrtimer_manager* owner;
};

void hrtimer_manager_init(struct hrtimer_manager* manager);
void hrtimer_arm_oneshot(
    struct hrtimer_manager* manager,
    struct hrtimer_event* timer,
    uint64_t delay_ns,
    timer_callback_t cb,
    void* ctx
);
void hrtimer_arm_periodic(
    struct hrtimer_manager* manager,
    struct hrtimer_event* timer,
    uint64_t interval_ns,
    timer_callback_t cb,
    void* ctx
);
bool hrtimer_cancel(struct hrtimer_event* timer);
void hrtimer_interrupt_tick(struct hrtimer_manager* manager);

#endif