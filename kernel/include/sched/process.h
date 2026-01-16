#ifndef KERNEL_SCHED_PROCESS_H
#define KERNEL_SCHED_PROCESS_H 1

#include <stddef.h>
#include <stdint.h>

#include "cpu/exception.h"
#include "drivers/timer.h"
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
} sched_policy_t;

typedef struct process {
    uint32_t pid;
    uint32_t thread_count;

    vm_space_t space;
    pagemap_t map;

    spinlock_t lock;
    struct rb_root thread_tree;

    bool is_kernel;
} process_t;

process_t* process_create(bool is_kernel);
void process_destroy(process_t* proc);

process_t* get_kernel_process(void);

typedef struct thread {
    uint32_t tid;
    thread_state_t state;
    process_t* owner;

    interrupt_trapframe_t tf;

    uintptr_t context_rsp;
    uintptr_t kernel_stack_top;

    void* kernel_stack;
    void* user_stack;

    size_t vruntime;
    size_t total_runtime;
    size_t last_start_time;

    uint32_t assigned_cpu;
    uint32_t affinity_mask;

    int nice;
    int nice_idx;

    sched_policy_t policy;
    int priorty;

    size_t arrival_time;
    size_t time_slice;

    size_t dl_deadline;
    size_t dl_period;
    size_t dl_runtime;
    size_t dl_remaining;

    size_t avg_load;
    size_t last_load_update;

    struct rb_node rb_node;
    struct rb_node process_node;

    timer_event_t sleep_timer;
    void* fpu_buffer;
} thread_t;

typedef struct {
    process_t* proc;
    void (*entry)(void*);
    void* arg;

    sched_policy_t policy;

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