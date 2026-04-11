#ifndef KERNEL_DRIVERS_LR_TIMER_H
#define KERNEL_DRIVERS_LR_TIMER_H 1

#include <stddef.h>
#include <stdint.h>

#include "libs/hashtable.h"
#include "libs/spinlock.h"

// Level 0 wheel with 256 buckets
#define TVR_BITS 8
#define TVR_SIZE (1ul << TVR_BITS)
#define TVR_MASK (TVR_SIZE - 1)

// Level 1-4 wheels with 64 buckets each
#define TVN_BITS 6
#define TVN_SIZE (1ul << TVN_BITS)
#define TVN_MASK (TVN_SIZE - 1)

typedef void (*timer_callback_t)(void*);

struct lrtimer_manager {
    struct hlist_head tv1[TVR_SIZE];
    struct hlist_head tv2[TVN_SIZE];
    struct hlist_head tv3[TVN_SIZE];
    struct hlist_head tv4[TVN_SIZE];
    struct hlist_head tv5[TVN_SIZE];

    uint64_t curr_time_ms;

    _Atomic(uint64_t) next_expires_at;
    _Atomic(size_t) active_timers;

    qspinlock_t lock;
};

struct lrtimer_event {
    struct hlist_node node;

    uint64_t expires_at;
    uint64_t interval;

    timer_callback_t callback;
    void* ctx;

    struct lrtimer_manager* owner;
};

void lrtimer_manager_init(struct lrtimer_manager* manager);
void lrtimer_arm_oneshot(
    struct lrtimer_manager* manager,
    struct lrtimer_event* timer,
    uint64_t delay_ms,
    timer_callback_t callback,
    void* ctx
);
void lrtimer_arm_periodic(
    struct lrtimer_manager* manager,
    struct lrtimer_event* timer,
    uint64_t interval_ms,
    timer_callback_t callback,
    void* ctx
);

bool lrtimer_cancel(struct lrtimer_event* timer);
void lrtimer_tick(struct lrtimer_manager* manager);

#endif