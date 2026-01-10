#include "sched/process.h"

#include <errno.h>
#include <stdatomic.h>
#include <string.h>

#include "boot/boot.h"
#include "boot/limine.h"
#include "cpu/exception.h"
#include "libs/list.h"
#include "libs/log.h"
#include "memory/heap.h"
#include "memory/memory.h"
#include "memory/pagemap.h"
#include "memory/vma.h"
#include "memory/vmm.h"

#define QUANTUM_BASE 20

static atomic_uint next_pid = 1;
static atomic_uint next_tid = 1;

static struct list_node global_process_list = LIST_INIT(global_process_list);

process_t* process_create(bool is_kernel) {
    process_t* proc = (process_t*)kmalloc(sizeof(process_t));

    if (!proc) {
        errno = ENOMEM;
        KLOG_WARN("PROC: failed to allocate process struct errno=%u\n", errno);
        return nullptr;
    }

    memset(proc, 0, sizeof(process_t));

    proc->pid = atomic_load_explicit(&next_pid, memory_order_relaxed);
    atomic_fetch_add_explicit(&next_pid, 1, memory_order_relaxed);

    list_init(&proc->thread_list);
    list_init(&proc->global_list);

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

    list_push_back(&global_process_list, &proc->global_list);

    KLOG_INFO("PROC: created pid=%u kernel=%u\n", proc->pid, is_kernel);

    return proc;
}

void process_destroy(process_t* proc) {
    if (!proc) {
        return;
    }

    while (!list_empty(&proc->thread_list)) {
        struct list_node* node = proc->thread_list.next;
        thread_t* t            = container_of(node, thread_t, process_node);
        thread_destroy(t);
    }

    if (!proc->is_kernel) {
        pagemap_release(&proc->map);
    }

    kfree(proc, sizeof(process_t));

    KLOG_INFO("PROC: destroyed pid=%u\n", proc->pid);
}

process_t* process_find_by_pid(int pid) {
    struct list_node* node;

    list_for_each(node, &global_process_list) {
        process_t* p = container_of(node, process_t, global_list);
        if (p->pid == pid) {
            return p;
        }
    }

    return nullptr;
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
    }
}

thread_t* thread_create(process_t* proc, void (*entry)(void*), void* arg) {
    thread_t* t = (thread_t*)kmalloc(sizeof(thread_t));

    if (!t) {
        errno = ENOMEM;
        KLOG_WARN("THREAD: failed to allocate thread errno=%u\n", errno);
        return nullptr;
    }

    memset(t, 0, sizeof(thread_t));

    t->tid = atomic_load_explicit(&next_tid, memory_order_relaxed);
    atomic_fetch_add_explicit(&next_tid, 1, memory_order_relaxed);

    t->owner           = proc;
    t->state           = THREAD_READY;
    t->priority        = 0;
    t->ticks_remaining = QUANTUM_BASE;

    if (!arch_thread_init(t, entry, arg)) {
        if (errno == 0) {
            errno = EINVAL;
        }

        KLOG_WARN("THREAD: arch init failed tid=%u errno=%u\n", t->tid, errno);
        kfree(t, sizeof(thread_t));
        return nullptr;
    }

    list_push_back(&proc->thread_list, &t->process_node);

    const char* state = thread_state_to_str(t->state);

    KLOG_DEBUG("THREAD: created tid=%u pid=%u state=%s\n", t->tid, proc->pid, state);

    return t;
}

void thread_destroy(thread_t* t) {
    if (!t) {
        return;
    }

    if (t->sched_node.next) {
        list_remove(&t->sched_node);
    }

    if (t->process_node.next) {
        list_remove(&t->process_node);
    }

    arch_thread_destroy(t);
    kfree(t, sizeof(thread_t));

    KLOG_DEBUG("THREAD: destroyed tid=%u pid=%u\n", t->tid, t->owner ? t->owner->pid : 0);
}

thread_t* thread_clone(process_t* target_proc, thread_t* parent, interrupt_trapframe_t* tf) {
    thread_t* child = thread_create(parent->owner, nullptr, nullptr);

    if (!child) {
        return nullptr;
    }

    memset(child, 0, sizeof(thread_t));
    child->tid   = atomic_fetch_add_explicit(&next_tid, 1, memory_order_relaxed);
    child->owner = target_proc;
    child->state = THREAD_READY;

    child->kernel_stack = vmm_alloc(
        &kernel_space,
        KSTACK_SIZE,
        VMM_FLAG_STACK | VMM_FLAG_WRITE | VMM_FLAG_READ,
        CACHE_WRITE_BACK,
        PAGE_SIZE_SMALL
    );

    if (!child->kernel_stack) {
        kfree(child, sizeof(thread_t));
        return nullptr;
    }

    child->kernel_stack_top = (uintptr_t)child->kernel_stack + KSTACK_SIZE;

    arch_thread_clone(child, tf);

    KLOG_DEBUG(
        "THREAD: cloned tid=%u from tid=%u pid=%u\n",
        child->tid,
        parent->tid,
        child->owner->pid
    );

    return child;
}