#ifndef KERNEL_SCHED_PROCESS_H
#define KERNEL_SCHED_PROCESS_H 1

#include <stddef.h>
#include <stdint.h>

#include "cpu/exception.h"
#include "drivers/timer.h"
#include "libs/dlist.h"
#include "libs/handles.h"
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
    PROCESS_ALIVE = 0,
    PROCESS_ZOMBIE,
    PROCESS_DEAD,
} process_state_t;

typedef enum {
    SCHED_NORMAL,
    SCHED_FIFO,
    SCHED_RR,
    SCHED_DEADLINE,
    SCHED_IDLE,
} sched_policy_t;

typedef struct process {
    char name[32];

    uint16_t state;
    bool is_kernel;
    int exit_code;

    int pid;
    uint32_t thread_count;

    vm_space_t space;
    pagemap_t map;

    spinlock_t lock;
    struct rb_root thread_tree;
    handle_table_t handle_table;

    struct process* parent;
    struct dlist_head children_list;
    struct dlist_head sibling_node;
    struct dlist_head wait_queue;
} process_t;

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

#define SCHED_DATA_PAYLOAD_SIZE 32
typedef struct {
    uint8_t payload[SCHED_DATA_PAYLOAD_SIZE];
    void* private_data;
} sched_entity_t;

typedef struct [[gnu::aligned(CACHE_LINE_SIZE)]] thread {
    char name[32];
    process_t* owner;

    uint32_t tid;
    uint32_t assigned_cpu;

    uint16_t state;
    uint8_t policy;
    uint8_t on_rq;

    int exit_code;
    uint32_t affinity_mask;

    sched_entity_t sched;
    struct sched_class* sched_class;

    size_t avg_load;
    size_t last_load_update;
    size_t preempt_count;

    uintptr_t context_rsp;
    uintptr_t kernel_stack_top;
    size_t last_start_time;

    struct rb_node rb_node;
    struct rb_node process_node;

    struct dlist_head wait_node;   // When this thread is blocked on a queue
    struct dlist_head join_queue;  // Threads waiting for this thread to exit

    void* kernel_stack;
    void* user_stack;

    timer_event_t sleep_timer;
    void* fpu_buffer;
} thread_t;

process_t* process_create(const char* name, process_t* parent, bool is_kernel);
void process_destroy(process_t* proc);
process_t* get_kernel_process(void);

[[noreturn]] void process_exit(int exit_code);
int process_wait(process_t* proc, int* exit_code);

// cfs: ... = nice
// dl: runtime, period
// rt: priority
thread_t* thread_create(
    const char* name,
    process_t* proc,
    uint8_t policy,
    void (*entry)(void*),
    void* args,
    ...
);
void thread_destroy(thread_t* t);
thread_t* thread_clone(process_t* target_proc, thread_t* parent, interrupt_trapframe_t* tf);

[[noreturn, gnu::used]] void thread_exit(int exit_code);
void thread_join(thread_t* t, int* exit_code);

bool arch_thread_init(thread_t* t, void (*entry)(void*), void* arg);
void arch_thread_destroy(thread_t* t);
void arch_thread_clone(thread_t* child, interrupt_trapframe_t* tf);

void reaper_task_entry(void* args);

void thread_save_fpu(thread_t* t);
void thread_restore_fpu(thread_t* t);

extern handle_table_t pid_handle_tbl;
extern handle_table_t tid_handle_tbl;

#endif