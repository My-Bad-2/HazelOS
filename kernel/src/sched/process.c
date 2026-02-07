#include "sched/process.h"

#include <errno.h>
#include <stdatomic.h>
#include <stdint.h>
#include <string.h>

#include "boot/boot.h"
#include "boot/limine.h"
#include "cpu/exception.h"
#include "cpu/smp.h"
#include "libs/handles.h"
#include "libs/log.h"
#include "libs/rb_tree.h"
#include "libs/spinlock.h"
#include "memory/heap.h"
#include "memory/memory.h"
#include "memory/pagemap.h"
#include "memory/vma.h"
#include "memory/vmm.h"
#include "sched/scheduler.h"

static handle_table_t pid_handle_tbl;
static handle_table_t tid_handle_tbl;

static kmem_cache_t* process_cache = nullptr;
static kmem_cache_t* thread_cache  = nullptr;

process_t* process_create(bool is_kernel) {
    if (!process_cache) {
        process_cache = kmem_cache_create("process_cache", sizeof(process_t), 8, 0, nullptr);
    }

    process_t* proc = kmem_cache_alloc(process_cache);

    if (!proc) {
        errno = ENOMEM;
        KLOG_WARN("PROC: failed to allocate process struct errno=%u\n", errno);
        return nullptr;
    }

    memset(proc, 0, sizeof(process_t));

    if (is_kernel) {
        handle_table_init(&pid_handle_tbl);
        handle_table_init(&tid_handle_tbl);
    }

    handle_table_init(&proc->handle_table);

    proc->pid = handle_alloc(&pid_handle_tbl, proc, 0);

    proc->thread_tree = RB_ROOT;
    create_spinlock(&proc->lock);

    if (is_kernel) {
        // Shared kernel map
        memcpy(&proc->map, vmm_get_kernel_pagemap(), sizeof(pagemap_t));
        memcpy(&proc->space, &kernel_space, sizeof(vm_space_t));

        proc->is_kernel = true;
    } else {
        pagemap_create(&proc->map);

        const uintptr_t user_va_start = 0x1000;
        uintptr_t user_va_end         = 0x00007FFFFFFFFFFF;  // 128 TiB

#ifdef __x86_64__
        if (paging_mode_request.response->mode == LIMINE_PAGING_MODE_X86_64_5LVL) {
            user_va_end = 0x00FFFFFFFFFFFFFF;  // 64 PiB
        }
#endif

        vmm_init_space(&proc->space, &proc->map, user_va_start, user_va_end);
    }

    KLOG_INFO("PROC: created pid=%u kernel=%u\n", proc->pid, is_kernel);

    return proc;
}

void process_destroy(process_t* proc) {
    if (!proc) {
        return;
    }

    acquire_spinlock(&proc->lock);

    while (proc->thread_tree.rb_node) {
        struct rb_node* node = rb_first(&proc->thread_tree);

        thread_t* t = rb_entry(node, thread_t, process_node);

        if (t == smp_current_core()->curr_thread) {
            rb_erase(&t->process_node, &proc->thread_tree);
            RB_CLEAR_NODE(&t->process_node);
            proc->thread_count--;
            continue;
        }

        rb_erase(&t->process_node, &proc->thread_tree);
        RB_CLEAR_NODE(&t->process_node);
        proc->thread_count--;

        release_spinlock(&proc->lock);

        thread_destroy(t);

        acquire_spinlock(&proc->lock);
    }

    release_spinlock(&proc->lock);

    if (!proc->is_kernel) {
        pagemap_release(&proc->map);
    }

    thread_t* curr = smp_current_core()->curr_thread;
    handle_free(&pid_handle_tbl, proc->pid);

    KLOG_INFO("PROC: destroyed pid=%u\n", proc->pid);

    if (curr && curr->owner == proc) {
        curr->owner = nullptr;
        kmem_cache_free(process_cache, proc);
        thread_destroy(curr);
    }

    kmem_cache_free(process_cache, proc);
}

static void process_insert_thread(process_t* p, thread_t* t) {
    struct rb_node** link  = &p->thread_tree.rb_node;
    struct rb_node* parent = nullptr;

    while (*link) {
        parent = *link;

        thread_t* entry = rb_entry(parent, thread_t, process_node);

        if (t->tid < entry->tid) {
            link = &parent->rb_left;
        } else {
            link = &parent->rb_right;
        }
    }

    rb_link_node(&t->process_node, parent, link);
    rb_insert_color(&t->process_node, &p->thread_tree);
}

static const char* thread_state_to_str(thread_state_t state) {
    switch (state) {
        case THREAD_READY:
            return "Ready";
        case THREAD_RUNNING:
            return "Running";
        case THREAD_BLOCKED:
            return "Blocked";
        case THREAD_TERMINATED:
            return "Terminated";
        case THREAD_SLEEPING:
            return "Sleeping";
    }
}

thread_t* thread_create(thread_create_args_t* args) {
    if (!thread_cache) {
        thread_cache = kmem_cache_create("thread_cache", sizeof(thread_t), 8, 0, nullptr);
    }

    if (!args || !args->entry) {
        errno = EINVAL;
        return nullptr;
    }

    if (args->policy == SCHED_DEADLINE) {
        if (args->dl.runtime == 0 || args->dl.period == 0 || args->dl.runtime > args->dl.period) {
            KLOG_WARN(
                "THREAD: Invalid DL params: runtime=%lu period=%lu\n",
                args->dl.runtime,
                args->dl.period
            );

            errno = EINVAL;
            return nullptr;
        }
    }

    thread_t* t = (thread_t*)kmem_cache_alloc(thread_cache);

    if (!t) {
        errno = ENOMEM;
        KLOG_WARN("THREAD: failed to allocate thread errno=%u\n", errno);
        return nullptr;
    }

    memset(t, 0, sizeof(thread_t));

    t->tid = handle_alloc(&tid_handle_tbl, t, 0);

    t->owner        = args->proc;
    t->state        = THREAD_READY;
    t->assigned_cpu = UINT32_MAX;
    t->policy       = args->policy;

    switch (t->policy) {
        case SCHED_DEADLINE:
            DL_DEADLINE(t) = args->dl.runtime;
            DL_PERIOD(t)   = args->dl.period;
            break;
        case SCHED_NORMAL:
            if (args->normal.nice < -20) {
                CFS_NICE(t) = -20;
            } else if (args->normal.nice > 19) {
                CFS_NICE(t) = 19;
            } else {
                CFS_NICE(t) = args->normal.nice;
            }

            CFS_NICE_IDX(t) = CFS_NICE(t) + 20;
            break;
        case SCHED_FIFO:
        case SCHED_RR:
            RT_PRIORITY(t) = args->rt.priority;
            if (RT_PRIORITY(t) < 0) {
                RT_PRIORITY(t) = 0;
            }

            if (RT_PRIORITY(t) > 99) {
                RT_PRIORITY(t) = 99;
            }

            if (t->policy == SCHED_RR) {
                RT_SLICE(t) = 0;
            }
            break;
        default:
            break;
    }

    if (!arch_thread_init(t, args->entry, args->arg)) {
        if (errno == 0) {
            errno = EINVAL;
        }

        KLOG_WARN("THREAD: arch init failed tid=%u errno=%u\n", t->tid, errno);
        kmem_cache_free(thread_cache, t);
        return nullptr;
    }

    if (args->proc) {
        acquire_spinlock(&args->proc->lock);

        process_insert_thread(args->proc, t);
        args->proc->thread_count++;

        release_spinlock(&args->proc->lock);
    }

    const char* state = thread_state_to_str(t->state);
    uint32_t pid      = args->proc ? args->proc->pid : 0;

    KLOG_DEBUG("THREAD: created tid=%u pid=%u state=%s policy=%d\n", t->tid, pid, state, t->policy);

    return t;
}

void thread_destroy(thread_t* t) {
    if (!t) {
        return;
    }

    scheduler_remove_thread(t);

    if (t->owner) {
        acquire_spinlock(&t->owner->lock);

        if (!RB_EMPTY_NODE(&t->process_node)) {
            rb_erase(&t->process_node, &t->owner->thread_tree);
            RB_CLEAR_NODE(&t->process_node);
            t->owner->thread_count--;
        }

        release_spinlock(&t->owner->lock);
    }

    KLOG_DEBUG("THREAD: destroyed tid=%u pid=%u\n", t->tid, t->owner ? t->owner->pid : 0);

    if (t == smp_current_core()->curr_thread) {
        t->state = THREAD_TERMINATED;
        scheduler_yield();
    }

    arch_thread_destroy(t);
    kmem_cache_free(thread_cache, t);
}

thread_t* thread_clone(process_t* target_proc, thread_t* parent, interrupt_trapframe_t* tf) {
    thread_t* child = (thread_t*)kmem_cache_alloc(thread_cache);

    if (!child) {
        errno = ENOMEM;
        return nullptr;
    }

    memset(child, 0, sizeof(thread_t));

    child->tid = handle_alloc(&tid_handle_tbl, child, 0);

    if (child->tid == 0) {
        kmem_cache_free(thread_cache, child);
        errno = ENOMEM;
        return nullptr;
    }

    child->owner        = target_proc;
    child->assigned_cpu = UINT32_MAX;
    child->state        = THREAD_READY;

    child->policy = parent->policy;

    switch (parent->policy) {
        case SCHED_DEADLINE:
            DL_PERIOD(child)  = DL_PERIOD(parent);
            DL_RUNTIME(child) = DL_RUNTIME(parent);
            break;
        case SCHED_NORMAL:
            CFS_NICE(child)     = CFS_NICE(parent);
            CFS_NICE_IDX(child) = CFS_NICE_IDX(parent);
            break;
        case SCHED_FIFO:
        case SCHED_RR:
            RT_PRIORITY(child) = RT_PRIORITY(parent);
            break;
        default:
            break;
    }

    child->kernel_stack = vmalloc(
        &kernel_space,
        KSTACK_SIZE,
        VMM_FLAG_STACK | VMM_FLAG_WRITE | VMM_FLAG_READ,
        CACHE_WRITE_BACK,
        PAGE_SIZE_SMALL
    );

    if (!child->kernel_stack) {
        handle_free(&tid_handle_tbl, child->tid);
        kmem_cache_free(thread_cache, child);
        return nullptr;
    }

    child->kernel_stack_top = (uintptr_t)child->kernel_stack + KSTACK_SIZE;

    arch_thread_clone(child, tf);

    if (target_proc) {
        acquire_spinlock(&target_proc->lock);

        process_insert_thread(target_proc, child);
        target_proc->thread_count++;
        release_spinlock(&target_proc->lock);
    }

    KLOG_DEBUG(
        "THREAD: cloned tid=%u from tid=%u pid=%u policy=%d\n",
        child->tid,
        parent->tid,
        child->owner->pid,
        child->policy
    );

    return child;
}