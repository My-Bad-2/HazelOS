#include "drivers/timer.h"
#ifndef KERNEL_SCHED_PROCESS_H
#define KERNEL_SCHED_PROCESS_H 1

#include <stddef.h>
#include <stdint.h>

#include "cpu/exception.h"
#include "libs/list.h"
#include "memory/pagemap.h"
#include "memory/vma.h"

typedef enum {
    THREAD_READY = 0,
    THREAD_RUNNING,
    THREAD_BLOCKED,
    THREAD_SLEEPING,
    THREAD_TERMINATED,
} thread_state_t;

typedef struct process {
    uint32_t pid;
    bool is_kernel;

    vm_space_t space;
    pagemap_t map;

    struct list_node thread_list;
    struct list_node global_list;
} process_t;

process_t* process_create(bool is_kernel);
void process_destroy(process_t* proc);

process_t* process_find_by_pid(int pid);
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

    int priority;
    int ticks_remaining;

    uint32_t cpu_affinity;  // Which CPU (s) this thread is allowed to run on
    uint32_t assigned_cpu;

    struct list_node sched_node;
    struct list_node process_node;

    timer_event_t sleep_timer;
    void* fpu_buffer;
} thread_t;

thread_t* thread_create(process_t* proc, void (*entry)(void*), void* arg);
void thread_destroy(thread_t* t);

bool arch_thread_init(thread_t* t, void (*entry)(void*), void* arg);
void arch_thread_destroy(thread_t* t);
void arch_thread_clone(thread_t* child, interrupt_trapframe_t* tf);

thread_t* thread_clone(process_t* target_proc, thread_t* parent, interrupt_trapframe_t* tf);

void thread_save_fpu(thread_t* t);
void thread_restore_fpu(thread_t* t);

#endif