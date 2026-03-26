#include "sched/process.h"

#include <errno.h>
#include <stdint.h>
#include <string.h>

#include "libs/dlist.h"
#include "libs/handles.h"
#include "libs/spinlock.h"
#include "memory/heap.h"
#include "memory/vma.h"
#include "memory/vmm.h"
#include "sched/sched_class.h"
#include "sched/scheduler.h"
#include "sched/wait.h"

handle_table_t pid_handle_tbl;
handle_table_t tid_handle_tbl;

static kmem_cache_t* process_cache = nullptr;
static qspinlock_t global_process_lock;

extern process_t* init_process;

process_t* process_create(const char* name, process_t* parent, bool is_kernel) {
    if (!process_cache) {
        process_cache =
            kmem_cache_create("process_cache", sizeof(process_t), _Alignof(process_t), 0, nullptr);
    }

    process_t* proc = kmem_cache_alloc(process_cache);
    if (!proc) {
        errno = ENOMEM;
        return nullptr;
    }

    memset(proc, 0, sizeof(process_t));
    memcpy(proc->name, name, sizeof(proc->name));

    if (is_kernel) {
        handle_table_init(&pid_handle_tbl);
        handle_table_init(&tid_handle_tbl);
    }

    handle_table_init(&proc->handle_table);
    proc->pid   = (int)handle_alloc(&pid_handle_tbl, proc, 0);
    proc->state = PROCESS_ALIVE;

    create_qspinlock(&proc->lock);

    dlist_init(&proc->thread_list);
    dlist_init(&proc->children_list);
    dlist_init(&proc->sibling_node);
    wait_queue_init(&proc->wait_queue);

    if (is_kernel) {
        memcpy(&proc->map, vmm_get_kernel_pagemap(), sizeof(pagemap_t));
        memcpy(&proc->space, kernel_space, sizeof(vm_space_t));
        proc->is_kernel = true;
    } else {
        pagemap_create(&proc->map);
        vmm_init_space(&proc->space, &proc->map, 0x1000, 0x00007FFFFFFFFFFF);
    }

    if (parent) {
        acquire_qspinlock(&global_process_lock);
        proc->parent = parent;
        dlist_add_tail(&proc->sibling_node, &parent->children_list);
        release_qspinlock(&global_process_lock);
    }

    return proc;
}

[[noreturn]] void process_exit(int exit_code) {
    process_t* proc = smp_current_core()->curr_thread->owner;

    acquire_qspinlock(&proc->lock);
    proc->state     = PROCESS_ZOMBIE;
    proc->exit_code = exit_code;
    release_qspinlock(&proc->lock);

    wait_queue_wake_up_all(&proc->wait_queue);
    thread_exit(exit_code);
}

int process_wait(process_t* proc, int* exit_code) {
    if (!proc) {
        return -1;
    }

    while (true) {
        thread_sleep_prepare(&proc->wait_queue);

        acquire_qspinlock(&proc->lock);
        bool is_done = (proc->state == PROCESS_ZOMBIE || proc->state == PROCESS_DEAD);

        if (is_done) {
            if (exit_code) {
                *exit_code = proc->exit_code;
            }

            proc->state = PROCESS_DEAD;
        }

        release_qspinlock(&proc->lock);

        if (is_done) {
            thread_sleep_finish(&proc->wait_queue);
            break;
        }

        scheduler_yield();
        thread_sleep_finish(&proc->wait_queue);
    }

    int pid = proc->pid;
    process_destroy(proc);

    return pid;
}

void process_destroy(process_t* proc) {
    if (!proc) {
        return;
    }

    acquire_qspinlock(&proc->lock);
    proc->state = PROCESS_DEAD;

    while (!dlist_empty(&proc->thread_list)) {
        struct dlist_head* node = proc->thread_list.next;
        thread_t* t             = dlist_entry(node, thread_t, process_node);

        dlist_del(node);
        dlist_init(&t->process_node);

        release_qspinlock(&proc->lock);

        thread_destroy(t);
        acquire_qspinlock(&proc->lock);
    }

    release_qspinlock(&proc->lock);

    wait_queue_wake_up_all(&proc->vfork_wait_queue);

    if (!proc->is_kernel) {
        pagemap_release(&proc->map);
    }

    acquire_qspinlock(&global_process_lock);

    while (!dlist_empty(&proc->children_list)) {
        struct dlist_head* child_node = proc->children_list.next;
        process_t* orphan             = dlist_entry(child_node, process_t, sibling_node);

        dlist_del(child_node);
        orphan->parent = init_process;
        dlist_add_tail(&orphan->sibling_node, &init_process->children_list);
    }

    if (!dlist_empty(&proc->sibling_node)) {
        dlist_del(&proc->sibling_node);
    }

    if (proc->parent) {
        wait_queue_wake_up_all(&proc->parent->wait_queue);
    }

    release_qspinlock(&global_process_lock);

    handle_free(&pid_handle_tbl, (uint32_t)proc->pid);
    kmem_cache_free(process_cache, proc);
}

process_t* process_clone(process_t* parent, uint64_t flags) {
    if (!parent) {
        return nullptr;
    }

    process_t* child = kmem_cache_alloc(process_cache);
    if (!child) {
        return nullptr;
    }

    memset(child, 0, sizeof(process_t));

    child->pid       = (int)handle_alloc(&pid_handle_tbl, child, 0);
    child->state     = PROCESS_ALIVE;
    child->is_kernel = false;
    create_qspinlock(&child->lock);

    dlist_init(&child->thread_list);
    dlist_init(&child->children_list);
    dlist_init(&child->sibling_node);

    wait_queue_init(&child->wait_queue);
    wait_queue_init(&child->vfork_wait_queue);

    strncpy(child->name, parent->name, 31);

    if (flags & CLONE_VM) {
        // Share address space
        child->space = parent->space;
        child->map   = parent->map;
    } else {
        if (!vmm_clone_space(&parent->space, &child->space, &child->map)) {
            handle_free(&pid_handle_tbl, (uint32_t)child->pid);
            kmem_cache_free(process_cache, child);
            return nullptr;
        }
    }

    child->parent = parent;

    acquire_qspinlock(&global_process_lock);
    dlist_add_tail(&child->sibling_node, &parent->children_list);
    release_qspinlock(&global_process_lock);

    return child;
}