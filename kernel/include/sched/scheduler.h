#ifndef KERNEL_SCHED_SCHEDULER_H
#define KERNEL_SCHED_SCHEDULER_H 1

#include "cpu/exception.h"
#include "sched/process.h"

#ifdef __cplusplus
extern "C" {
#endif

void scheduler_init(void);
bool scheduler_is_initialized(void);

void scheduler_add_thread(thread_t* t);
void scheduler_remove_thread(thread_t* t);

void scheduler_renice(thread_t* t, int nice);
void scheduler_block(void);
void scheduler_unblock(thread_t* t);
void scheduler_sleep(size_t ms);

void scheduler_handler(interrupt_trapframe_t* tf);
void scheduler_yield(void);

#ifdef __cplusplus
}
#endif

#endif