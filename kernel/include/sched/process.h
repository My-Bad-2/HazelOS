#include "libs/handles.h"
#ifndef KERNEL_SCHED_PROCESS_H
#define KERNEL_SCHED_PROCESS_H 1

#include <stddef.h>
#include <stdint.h>

#include "cpu/exception.h"
#include "drivers/timer.h"
#include "libs/dlist.h"
#include "libs/rb_tree.h"
#include "libs/spinlock.h"
#include "memory/pagemap.h"
#include "memory/vma.h"

typedef enum {
    THREAD_READY = 0,
    THREAD_RUNNING,
    THREAD_BLOCKED,
    THREAD_SLEEPING,
    THREAD_TERMINATED,
} thread_state_t;

typedef enum {
    SCHED_NORMAL,
    SCHED_FIFO,
    SCHED_RR,
    SCHED_DEADLINE,
    SCHED_IDLE,
} sched_policy_t;

typedef struct process {
    uint32_t pid;
    uint32_t thread_count;

    vm_space_t space;
    pagemap_t map;

    spinlock_t lock;
    struct rb_root thread_tree;

    handle_table_t handle_table;

    bool is_kernel;
} process_t;

process_t* process_create(bool is_kernel);
void process_destroy(process_t* proc);

process_t* get_kernel_process(void);

union sched_entity {
    struct {
        size_t vruntime;
        size_t total_runtime;
        int nice;
        int nice_idx;
    } cfs;

    struct {
        size_t arrival_time;
        size_t time_slice;
        int priority;
    } rt;

    struct {
        size_t deadline;
        size_t period;
        size_t runtime;
        size_t remaining;
    } dl;
};

typedef struct [[gnu::aligned(CACHE_LINE_SIZE)]] thread {
    process_t* owner;

    uint32_t tid;
    uint32_t assigned_cpu;

    uint16_t state;
    uint8_t policy;
    uint8_t on_rq;

    uint32_t affinity_mask;

    union sched_entity sched;
    struct sched_class* sched_class;

    size_t avg_load;
    size_t last_load_update;

    uintptr_t context_rsp;
    uintptr_t kernel_stack_top;

    size_t last_start_time;

    struct rb_node rb_node;
    struct rb_node process_node;
    struct dlist_head wait_node;

    void* kernel_stack;
    void* user_stack;

    timer_event_t sleep_timer;
    void* fpu_buffer;
} thread_t;

#define CFS_VRUNTIME(t)      ((t)->sched.cfs.vruntime)
#define CFS_TOTAL_RUNTIME(t) ((t)->sched.cfs.total_runtime)
#define CFS_NICE(t)          ((t)->sched.cfs.nice)
#define CFS_NICE_IDX(t)      ((t)->sched.cfs.nice_idx)

#define RT_ARRIVAL(t)  ((t)->sched.rt.arrival_time)
#define RT_SLICE(t)    ((t)->sched.rt.time_slice)
#define RT_PRIORITY(t) ((t)->sched.rt.priority)

#define DL_DEADLINE(t)  ((t)->sched.dl.deadline)
#define DL_PERIOD(t)    ((t)->sched.dl.period)
#define DL_RUNTIME(t)   ((t)->sched.dl.runtime)
#define DL_REMAINING(t) ((t)->sched.dl.remaining)

typedef struct {
    process_t* proc;
    void (*entry)(void*);
    void* arg;

    uint8_t policy;

    union {
        struct {
            int nice;
        } normal;

        struct {
            int priority;
        } rt;

        struct {
            size_t runtime;  // Execution budget
            size_t period;   // Period window
        } dl;
    };
} thread_create_args_t;

thread_t* thread_create(thread_create_args_t* args);

void thread_destroy(thread_t* t);

bool arch_thread_init(thread_t* t, void (*entry)(void*), void* arg);
void arch_thread_destroy(thread_t* t);
void arch_thread_clone(thread_t* child, interrupt_trapframe_t* tf);

thread_t* thread_clone(process_t* target_proc, thread_t* parent, interrupt_trapframe_t* tf);

void thread_save_fpu(thread_t* t);
void thread_restore_fpu(thread_t* t);

#endif