#ifndef KERNEL_SCHED_SCHEDULER_H
#define KERNEL_SCHED_SCHEDULER_H 1

#include "cpu/exception.h"
#include "sched/process.h"

#ifdef __cplusplus
extern "C" {
#endif

#define COST_SMT_THREAD   500
#define MIGRATION_COST_NS 50000

void scheduler_init(void);
bool scheduler_is_initialized(void);

void scheduler_add_thread(thread_t* t);
void scheduler_remove_thread(thread_t* t);

void scheduler_renice(thread_t* t, int nice);
void scheduler_block(void);
void scheduler_unblock(thread_t* t);
void scheduler_sleep(size_t ms);

void schedule(void);
void scheduler_yield(void);
void scheduler_check_reschedule(interrupt_trapframe_t* tf);

#ifdef __cplusplus
}
#endif

#endif