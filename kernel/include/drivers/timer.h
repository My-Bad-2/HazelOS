#ifndef KERNEL_DRIVERS_TIMER_H
#define KERNEL_DRIVERS_TIMER_H 1

#include <stddef.h>
#include <stdint.h>

#include "drivers/arch_timer.h"
#include "libs/hashtable.h"
#include "libs/spinlock.h"

#ifdef __cplusplus
extern "C" {
#endif

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

    size_t curr_ticks;
    volatile size_t active_timers;

    qspinlock_t lock;
    volatile uint32_t next_expires_at;
} timer_manager_t;

typedef struct {
    struct hlist_node node;

    size_t expires_at;
    size_t interval;

    timer_callback_t callback;
    void* ctx;

    timer_manager_t* owner;
} timer_event_t;

void timer_set_clock_source(clock_source_t source);
void timer_mdelay(size_t ms);
void timer_udelay(size_t us);
void timer_configure(timer_mode_t mode, uint8_t vector, size_t count);

size_t timer_get_time(void);
size_t timer_get_time_ms(void);
size_t timer_get_hz(void);

void timer_tick(void);
void timer_init(void);

void timer_manager_init(timer_manager_t* manager);
void timer_arm(
    timer_manager_t* manager,
    timer_event_t* timer,
    uint64_t delay,
    uint64_t interval_ticks,
    timer_callback_t callback,
    void* ctx
);

bool timer_cancel(timer_event_t* timer);
void timer_manager_tick(timer_manager_t* manager);

#ifdef __cplusplus
}
#endif

#endif