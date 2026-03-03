#ifndef KERNEL_SCHED_CLASS_H
#define KERNEL_SCHED_CLASS_H 1

#include <stdarg.h>

#include "cpu/smp.h"
#include "sched/process.h"

struct sched_class {
    const char* name;
    int priority;
    int policy_id;

    struct sched_class* next;

    void (*init_task)(thread_t* t, va_list args);
    void (*renice_task)(per_cpu_data_t* rq, thread_t* t, int nice);

    void (*enqueue_task)(per_cpu_data_t* rq, thread_t* t);
    void (*dequeue_task)(per_cpu_data_t* rq, thread_t* t);
    void (*yield_task)(per_cpu_data_t* rq, thread_t* t);
    void (*task_tick)(per_cpu_data_t* rq, thread_t* t, size_t now);
    void (*task_unblock)(per_cpu_data_t* rq, thread_t* t);

    thread_t* (*pick_next_task)(per_cpu_data_t* rq);
    thread_t* (*steal_task)(per_cpu_data_t* busiest_cpu, per_cpu_data_t* this_cpu);
    bool (*check_preempt)(thread_t* new_task, thread_t* curr_task);
};

void sched_class_init(void);
void sched_class_register(struct sched_class* sc);
bool sched_class_unregister(struct sched_class* sc);

struct sched_class* get_sched_class(int policy_id);

extern struct sched_class* sched_classes_head;

extern struct sched_class cfs_sched_class;
extern struct sched_class rt_rr_sched_class;
extern struct sched_class rt_fifo_sched_class;
extern struct sched_class dl_sched_class;
extern struct sched_class idle_sched_class;

#endif