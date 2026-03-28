#include "sched/process.h"

#include <stdint.h>
#include <string.h>

#include "core/capability.h"
#include "libs/dlist.h"
#include "libs/handles.h"
#include "libs/kobject.h"
#include "libs/spinlock.h"
#include "memory/heap.h"
#include "memory/pagemap.h"
#include "memory/vma.h"
#include "memory/vmm.h"
#include "sched/sched_class.h"
#include "sched/scheduler.h"
#include "sched/wait.h"

static kmem_cache_t* process_cache = nullptr;
extern process_t* init_process;
static qspinlock_t global_process_lock;

static void capability_bootstrap_injection(
    struct process* parent,
    struct process* child,
    uint64_t* proc_cap_id,
    uint64_t* cnode_cap_id
) {
    uint64_t parent_proc_cap_id;
    struct capability* proc_cap = cap_alloc(parent->root_cnode, &parent_proc_cap_id);

    if (proc_cap_id) {
        *proc_cap_id = parent_proc_cap_id;
    }

    uint64_t parent_cnode_cap_id;
    struct capability* cnode_cap = cap_alloc(parent->root_cnode, &parent_cnode_cap_id);

    if (cnode_cap_id) {
        *cnode_cap_id = parent_cnode_cap_id;
    }

    acquire_qspinlock(&proc_cap->lock);
    atomic_store_explicit(&proc_cap->object_ptr, (uintptr_t)child, memory_order_release);
    proc_cap->type   = CAP_TYPE_PROCESS;
    proc_cap->rights = RIGHT_ALL;
    release_qspinlock(&proc_cap->lock);

    acquire_qspinlock(&cnode_cap->lock);
    atomic_store_explicit(
        &cnode_cap->object_ptr,
        (uintptr_t)child->root_cnode,
        memory_order_release
    );
    cnode_cap->type   = CAP_TYPE_CNODE;
    cnode_cap->rights = RIGHT_ALL;
    release_qspinlock(&cnode_cap->lock);
}

process_t* process_create(const char* name, bool is_kernel) {
    if (!process_cache) {
        process_cache =
            kmem_cache_create("process_cache", sizeof(process_t), _Alignof(process_t), 0, nullptr);
    }

    process_t* proc = kmem_cache_alloc(process_cache);
    if (!proc) {
        return nullptr;
    }

    memset(proc, 0, sizeof(process_t));
    kref_init(&proc->kobj, CAP_TYPE_PROCESS);
    proc->state      = PROCESS_ALIVE;
    proc->is_kernel  = is_kernel;
    proc->root_cnode = create_cspace();

#if KERNEL_DEBUG
    strncpy(proc->name, name, sizeof(proc->name) - 1);
#else
    (void)name;
#endif
    create_qspinlock(&proc->lock);
    dlist_init(&proc->thread_list);
    dlist_init(&proc->children_list);
    dlist_init(&proc->sibling_node);
    wait_queue_init(&proc->wait_queue);
    wait_queue_init(&proc->vfork_wait_queue);

    if (is_kernel) {
        memcpy(&proc->map, vmm_get_kernel_pagemap(), sizeof(pagemap_t));
        memcpy(&proc->space, kernel_space, sizeof(vm_space_t));
    } else {
        pagemap_create(&proc->map);
        vmm_init_space(&proc->space, &proc->map, 0x1000, 0x00007fffffffffff);
    }

    return proc;
}

process_t* process_clone(
    process_t* parent,
    uint64_t flags,
    uint64_t* parent_proc_cap_id,
    uint64_t* parent_cnode_id
) {
    if (!parent) {
        return nullptr;
    }

    process_t* child = kmem_cache_alloc(process_cache);
    if (!child) {
        return nullptr;
    }

    memset(child, 0, sizeof(process_t));
    kref_init(&child->kobj, CAP_TYPE_PROCESS);
    child->state      = PROCESS_ALIVE;
    child->root_cnode = create_cspace();

#if KERNEL_DEBUG
    strncpy(child->name, parent->name, sizeof(child->name) - 1);
#endif
    create_qspinlock(&child->lock);
    dlist_init(&child->thread_list);
    dlist_init(&child->children_list);
    dlist_init(&child->sibling_node);
    wait_queue_init(&child->wait_queue);
    wait_queue_init(&child->vfork_wait_queue);

    if (flags & CLONE_VM) {
        // Share address space
        child->space = parent->space;
        child->map   = parent->map;
    } else {
        if (!vmm_clone_space(&parent->space, &child->space, &child->map)) {
            kmem_cache_free(process_cache, child);
            return nullptr;
        }
    }

    capability_bootstrap_injection(parent, child, parent_proc_cap_id, parent_cnode_id);
    child->parent = parent;

    acquire_qspinlock(&global_process_lock);
    dlist_add_tail(&child->sibling_node, &parent->children_list);
    release_qspinlock(&global_process_lock);

    return child;
}

uint64_t process_wait(process_t* proc, int* exit_code) {
    if (!proc) {
        return 0;
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

    uint64_t koid = proc->kobj.koid;
    kref_put(&proc->kobj, process_release);
    return koid;
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

void process_release(struct kobject* obj) {
    if (!obj) {
        return;
    }

    process_t* proc = kref_entry(obj, struct process, kobj);
    wait_queue_wake_up_all(&proc->vfork_wait_queue);

    if (!proc->is_kernel) {
        pagemap_release(&proc->map);
    }

    acquire_qspinlock(&proc->lock);

    while (!dlist_empty(&proc->children_list)) {
        struct dlist_head* node = proc->children_list.next;
        struct process* orphan  = dlist_entry(node, struct process, sibling_node);

        dlist_del(node);
        orphan->parent = init_process;
        dlist_add_tail(&orphan->sibling_node, &init_process->children_list);
    }

    if (!dlist_empty(&proc->sibling_node)) {
        dlist_del(&proc->sibling_node);
    }

    if (proc->parent) {
        wait_queue_wake_up_all(&proc->parent->wait_queue);
    }

    destroy_cspace(proc->root_cnode);

    release_qspinlock(&global_process_lock);
    kmem_cache_free(process_cache, proc);
}