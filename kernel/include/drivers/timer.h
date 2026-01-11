#ifndef KERNEL_DRIVERS_TIMER_H
#define KERNEL_DRIVERS_TIMER_H 1

#include <stddef.h>
#include <stdint.h>

#include "drivers/arch_timer.h"
#include "libs/list.h"
#include "libs/spinlock.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef void (*timer_callback_t)(void*);

typedef struct {
    struct list_node head;
    size_t curr_ticks;
    spinlock_t lock;
} timer_manager_t;

typedef struct {
    struct list_node node;

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

void timer_tick(void);
void timer_init(void);

void timer_manager_init(timer_manager_t* manager);
void timer_arm_oneshot(
    timer_manager_t* manager,
    timer_event_t* timer,
    uint64_t delay,
    timer_callback_t callback,
    void* ctx
);

void timer_arm_periodic(
    timer_manager_t* manager,
    timer_event_t* timer,
    uint64_t interval,
    timer_callback_t callback,
    void* ctx
);

bool timer_cancel(timer_event_t* timer);
void timer_manager_tick(timer_manager_t* manager);

#ifdef __cplusplus
}
#endif

#endif