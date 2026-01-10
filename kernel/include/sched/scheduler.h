#ifndef KERNEL_SCHED_SCHEDULER_H
#define KERNEL_SCHED_SCHEDULER_H 1

#include "cpu/exception.h"
#include "sched/process.h"

#ifdef __cplusplus
extern "C" {
#endif

void scheduler_init(void);
void scheduler_add_thread(thread_t* t);
void scheduler_remove_thread(thread_t* t);
void scheduler_yield(void);

bool scheduler_is_initialized(void);

void scheduler_handler(interrupt_trapframe_t* tf);

#ifdef __cplusplus
}
#endif

#endif