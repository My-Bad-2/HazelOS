#include "sched/process.h"

#include <errno.h>
#include <string.h>

#include "libs/dlist.h"
#include "libs/handles.h"
#include "libs/spinlock.h"
#include "memory/heap.h"
#include "memory/vmm.h"
#include "sched/sched_class.h"
#include "sched/scheduler.h"

handle_table_t pid_handle_tbl;
handle_table_t tid_handle_tbl;

static kmem_cache_t* process_cache = nullptr;
static spinlock_t global_process_lock;

static void wake_up_all(struct dlist_head* queue) {
    struct thread* curr = nullptr;

    dlist_for_each_entry(curr, queue, wait_node) {
        dlist_del(&curr->wait_node);
        dlist_del(&curr->wait_node);

        scheduler_unblock(curr);
    }
}

static void sleep_on_queue(struct dlist_head* queue) {
    thread_t* curr = smp_current_core()->curr_thread;
    dlist_add_tail(&curr->wait_node, queue);
    scheduler_block();
}

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

    create_spinlock(&proc->lock);
    proc->thread_tree = RB_ROOT;

    dlist_init(&proc->children_list);
    dlist_init(&proc->sibling_node);
    dlist_init(&proc->wait_queue);

    if (is_kernel) {
        memcpy(&proc->map, vmm_get_kernel_pagemap(), sizeof(pagemap_t));
        memcpy(&proc->space, kernel_space, sizeof(vm_space_t));
        proc->is_kernel = true;
    } else {
        pagemap_create(&proc->map);
        vmm_init_space(&proc->space, &proc->map, 0x1000, 0x00007FFFFFFFFFFF);
    }

    if (parent) {
        acquire_spinlock(&global_process_lock);
        proc->parent = parent;
        dlist_add_tail(&proc->sibling_node, &parent->children_list);
        release_spinlock(&global_process_lock);
    }

    return proc;
}

[[noreturn]] void process_exit(int exit_code) {
    process_t* proc = smp_current_core()->curr_thread->owner;

    acquire_spinlock(&proc->lock);
    proc->state     = PROCESS_ZOMBIE;
    proc->exit_code = exit_code;

    wake_up_all(&proc->wait_queue);
    release_spinlock(&proc->lock);

    thread_exit(exit_code);
}

int process_wait(process_t* proc, int* exit_code) {
    if (!proc) {
        return -1;
    }

    acquire_spinlock(&proc->lock);

    while (proc->state != PROCESS_ZOMBIE && proc->state != PROCESS_DEAD) {
        release_spinlock(&proc->lock);
        sleep_on_queue(&proc->wait_queue);
        acquire_spinlock(&proc->lock);
    }

    if (exit_code) {
        *exit_code = proc->exit_code;
    }

    proc->state = PROCESS_DEAD;
    release_spinlock(&proc->lock);

    process_destroy(proc);
    return proc->pid;
}

void process_destroy(process_t* proc) {}