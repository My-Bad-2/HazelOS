#ifndef KERNEL_DRIVERS_KTIMER_H
#define KERNEL_DRIVERS_KTIMER_H 1

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

typedef struct {
    struct hlist_head tv1[TVR_SIZE];
    struct hlist_head tv2[TVN_SIZE];
    struct hlist_head tv3[TVN_SIZE];
    struct hlist_head tv4[TVN_SIZE];
    struct hlist_head tv5[TVN_SIZE];

    uint64_t curr_time_ms;

    volatile uint64_t next_expires_at;
    volatile size_t active_timers;

    qspinlock_t lock;
} timer_manager_t;

typedef struct {
    struct hlist_node node;

    uint64_t expires_at;
    uint64_t interval;

    timer_callback_t callback;
    void* ctx;

    timer_manager_t* owner;
} timer_event_t;

void timer_manager_init(timer_manager_t* manager);
void timer_arm_oneshot(
    timer_manager_t* manager,
    timer_event_t* timer,
    uint64_t delay_ms,
    timer_callback_t callback,
    void* ctx
);
void timer_arm_periodic(
    timer_manager_t* manager,
    timer_event_t* timer,
    uint64_t interval_ms,
    timer_callback_t callback,
    void* ctx
);

bool timer_cancel(timer_event_t* timer);
void timer_manager_tick(timer_manager_t* manager);

#endif