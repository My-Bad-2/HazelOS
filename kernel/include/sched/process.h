#ifndef KERNEL_SCHED_PROCESS_H
#define KERNEL_SCHED_PROCESS_H 1

#include <stddef.h>
#include <stdint.h>

#include "cpu/syscalls.h"
#include "drivers/ktimer.h"
#include "libs/dlist.h"
#include "libs/handles.h"
#include "libs/kobject.h"
#include "libs/rb_tree.h"
#include "libs/spinlock.h"
#include "memory/vma.h"
#include "sched/ipc.h"
#include "sched/wait.h"

#define MAX_RT_PRIO 100

// Creates a new thread inside the caller's process, otherwise create a new process
#define CLONE_INTO_CURRENT_PROCESS (1 << 0)
// Child shares the parent's vspace otherise perform a deep-copy (CoW) of the VSpace
#define CLONE_SHARE_VSPACE (1 << 1)
// The kernel deep-copies the parent's CNode tree to the child.
#define CLONE_COPY_CSPACE (1 << 2)
// The new thread is created in THREAD_SUSPENDED state, the paent must explicityl start it via IPC
#define CLONE_SUSPENDED (1 << 3)
// The parent thread yields the CPU immediately so the child can run.
#define CLONE_VFORK (1 << 4)

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
    struct kobject kobj;

    uint16_t state;
    bool is_kernel;
    int exit_code;
    struct process* parent;

    struct vm_space* vspace;
    struct cnode* root_cnode;

    alignas(CACHE_LINE_SIZE) qspinlock_t lock;
    uint32_t thread_count;
    struct dlist_head thread_list;
    struct dlist_head children_list;
    struct dlist_head sibling_node;

    struct wait_queue wait_queue;
    struct wait_queue vfork_wait_queue;

#if KERNEL_DEBUG
    char name[32];
#endif
} process_t;

#define SCHED_DATA_PAYLOAD_SIZE 32
typedef struct {
    uint8_t payload[SCHED_DATA_PAYLOAD_SIZE];
    void* private_data;
} sched_entity_t;

typedef struct [[gnu::aligned(CACHE_LINE_SIZE)]] thread {
    struct kobject kobj;
    process_t* owner;

    uintptr_t context_rsp;
    void* kernel_stack;
    uintptr_t kernel_stack_top;
    void* fpu_buffer;

    uint16_t state;
    uint8_t policy;
    uint8_t on_rq;
    int exit_code;
    uint32_t assigned_cpu;
    uint32_t affinity_mask;

#if KERNEL_DEBUG
    char name[32];
#endif

    alignas(CACHE_LINE_SIZE) sched_entity_t sched;
    struct sched_class* sched_class;
    size_t avg_load;
    size_t last_load_update;
    size_t preempt_count;
    size_t last_start_time;

    union {
        struct rb_node rb_node;
        struct dlist_head run_node;
    };

    struct dlist_head process_node;
    struct dlist_head wait_node;

    timer_event_t sleep_timer;
    struct thread_ipc_state ipc_state;
    struct wait_queue join_queue;
    qspinlock_t lock;
} thread_t;

process_t*
process_create(const char* name, bool is_kernel, struct vm_space* vspace, int* error_code);

process_t* process_clone(process_t* parent, uint64_t flags, int* error_code);
void process_release(struct kobject* kobj);

[[noreturn]] void process_exit(int exit_code);
uint64_t process_wait(process_t* proc, int* exit_code);

process_t* get_kernel_process(void);

// cfs: ... = nice
// dl: runtime, period
// rt: priority
thread_t* thread_create(
    const char* name,
    process_t* proc,
    struct vm_space* space,
    uint8_t policy,
    uintptr_t entry_rip,
    uint64_t args,
    uintptr_t user_rsp,
    int* err_code,
    ...
);
void thread_release(struct kobject* kobj);
thread_t* thread_clone(
    process_t* target_proc,
    thread_t* parent,
    struct syscall_regs* regs,
    uintptr_t rsp_override,
    uintptr_t rip_override,
    int* error_code
);

[[noreturn, gnu::used]] void thread_exit(int exit_code);
void thread_wait(thread_t* t, int* exit_code);
void thread_join(thread_t* t, int* exit_code);

int arch_thread_init(thread_t* t, uintptr_t entry_rip, uint64_t arg, uintptr_t user_rsp);
void arch_thread_destroy(thread_t* t);
int arch_thread_clone(
    thread_t* child,
    thread_t* parent,
    struct syscall_regs* tf,
    uintptr_t rsp_override,
    uintptr_t rip_override
);

void reaper_task_entry(void* args);
void thread_save_fpu(thread_t* t);
void thread_restore_fpu(thread_t* t);

#endif