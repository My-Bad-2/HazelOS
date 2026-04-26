#ifndef KERNEL_SCHED_SCHEDULER_H
#define KERNEL_SCHED_SCHEDULER_H 1

#include "cpu/exception.h"
#include "sched/process.h"

#ifdef __cplusplus
extern "C" {
#endif

#define COST_SMT_THREAD   500
#define MIGRATION_COST_NS 50000

struct per_cpu_data;

void scheduler_init(void);
void scheduler_arch_init(void);
void scheduler_init_kernel_process(void);
void scheduler_init_per_cpu(struct per_cpu_data* cpu);
bool scheduler_is_initialized(void);
void scheduler_tick(void);

void scheduler_add_thread(thread_t* t);
void scheduler_remove_thread(thread_t* t);

int scheduler_renice(thread_t* t, int nice);
void scheduler_block(void);
int scheduler_block_timeout(int64_t timeout_ms);
void scheduler_unblock(thread_t* t);
int scheduler_sleep(int64_t timeout_ms);

void schedule(void);
void scheduler_yield(void);
void scheduler_directed_yield(thread_t* target);
void scheduler_check_reschedule(struct interrupt_trapframe* tf);

void preempt_disable();
void preempt_enable();
uint32_t preempt_count(void);

#ifdef __cplusplus
}
#endif

#endif