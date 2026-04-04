#include "sched/process.h"

#include <errno.h>
#include <stdatomic.h>
#include <stdint.h>
#include <string.h>

#include "compiler.h"
#include "core/capability.h"
#include "core/posix_emul.h"
#include "cpu/smp.h"
#include "libs/dlist.h"
#include "libs/handles.h"
#include "libs/kobject.h"
#include "libs/spinlock.h"
#include "memory/heap.h"
#include "memory/pagemap.h"
#include "memory/vma.h"
#include "memory/vmm.h"
#include "sched/scheduler.h"
#include "sched/wait.h"

static kmem_cache_t* process_cache = nullptr;
extern process_t* init_process;
static qspinlock_t global_process_lock;

static bool capability_bootstrap_injection(
    struct process* parent,
    struct process* child,
    uint64_t* proc_cap_id,
    uint64_t* cnode_cap_id,
    uint64_t* vspace_cap_id
) {
    uint64_t p_cap_id, v_cap_id, c_cap_id;
    struct capability* proc_cap   = cap_alloc(parent->root_cnode, &p_cap_id);
    struct capability* cnode_cap  = cap_alloc(parent->root_cnode, &c_cap_id);
    struct capability* vspace_cap = cap_alloc(parent->root_cnode, &v_cap_id);

    if (unlikely(!proc_cap || !cnode_cap || !vspace_cap)) {
        if (proc_cap) cap_close(parent->root_cnode, p_cap_id);
        if (cnode_cap) cap_close(parent->root_cnode, c_cap_id);
        if (vspace_cap) cap_close(parent->root_cnode, v_cap_id);
        return false;
    }

    if (proc_cap_id) *proc_cap_id = p_cap_id;
    if (cnode_cap_id) *cnode_cap_id = c_cap_id;
    if (vspace_cap_id) *vspace_cap_id = v_cap_id;

    acquire_qspinlock(&proc_cap->lock);
    atomic_store_explicit(&proc_cap->object_ptr, (uintptr_t)child, memory_order_release);
    proc_cap->type   = CAP_TYPE_PROCESS;
    proc_cap->rights = RIGHT_ALL & ~RIGHT_CLOEXEC;
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

    acquire_qspinlock(&vspace_cap->lock);
    kref_get(&child->vspace->refcount);
    atomic_store_explicit(&vspace_cap->object_ptr, (uintptr_t)child->vspace, memory_order_release);
    vspace_cap->type   = CAP_TYPE_VSPACE;
    vspace_cap->rights = RIGHT_ALL;
    release_qspinlock(&vspace_cap->lock);

    return true;
}

process_t* process_create(const char* name, bool is_kernel) {
    if (!process_cache) {
        process_cache = kmem_cache_create(
            "process_cache",
            sizeof(struct process),
            _Alignof(struct process),
            SLAB_NEVER_MERGE | SLAB_HWCACHE_ALIGN,
            nullptr
        );
    }

    process_t* proc = kmem_cache_alloc(process_cache);
    if (unlikely(!proc)) return nullptr;

    memset(proc, 0, sizeof(process_t));
    kref_init(&proc->kobj, CAP_TYPE_PROCESS);
    proc->state      = PROCESS_ALIVE;
    proc->is_kernel  = is_kernel;
    proc->root_cnode = create_cspace();
#if KERNEL_DEBUG
    if (likely(name)) strncpy(proc->name, name, sizeof(proc->name) - 1);
#else
    (void)name;
#endif

    create_qspinlock(&proc->lock);
    create_qspinlock(&proc->posix_lock);

    dlist_init(&proc->posix_children);
    dlist_init(&proc->thread_list);
    dlist_init(&proc->children_list);
    dlist_init(&proc->sibling_node);

    wait_queue_init(&proc->wait_queue);
    wait_queue_init(&proc->vfork_wait_queue);

    if (is_kernel) {
        proc->map    = vmm_get_kernel_pagemap();
        proc->vspace = kernel_space;

        vmm_init_space(kernel_space, proc);
        kref_get(&kernel_space->refcount);
    } else {
        proc->map    = pagemap_create();
        proc->vspace = vmm_create_space(proc);

        if (!proc->vspace) {
            pagemap_release(proc->map);
            destroy_cspace(proc->root_cnode);
            kmem_cache_free(process_cache, proc);
            return nullptr;
        }
    }

    uint64_t v_cap_id        = 0;
    struct capability* v_cap = cap_alloc(proc->root_cnode, &v_cap_id);
    if (!v_cap) {
        kref_put(&proc->vspace->refcount, vmm_space_release);
        pagemap_release(proc->map);
        destroy_cspace(proc->root_cnode);
        kmem_cache_free(process_cache, proc);
        return nullptr;
    }

    v_cap->badge  = 0;
    v_cap->type   = CAP_TYPE_VSPACE;
    v_cap->rights = RIGHT_ALL & ~RIGHT_CLOEXEC;
    kref_get(&proc->vspace->refcount);
    atomic_store_explicit(&v_cap->object_ptr, (uintptr_t)proc->vspace, memory_order_relaxed);
    atomic_init(&v_cap->generation, 1);

    return proc;
}

process_t* process_clone(
    process_t* parent,
    uint64_t flags,
    uint64_t* parent_proc_cap_id,
    uint64_t* parent_cnode_id,
    uint64_t* parent_vspace_id
) {
    if (unlikely(!parent)) return nullptr;

    process_t* child = kmem_cache_alloc(process_cache);
    if (unlikely(!child)) return nullptr;

    memset(child, 0, sizeof(process_t));
    kref_init(&child->kobj, CAP_TYPE_PROCESS);
    child->state      = PROCESS_ALIVE;
    child->root_cnode = cnode_clone(parent->root_cnode);
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
        child->vspace = parent->vspace;
        child->map    = parent->map;
        kref_get(&child->vspace->refcount);
    } else {
        child->map    = pagemap_create();
        child->vspace = vmm_create_space(child);

        if (!vmm_clone_space(parent->vspace, child->vspace)) {
            if (child->vspace) kref_put(&child->vspace->refcount, vmm_space_release);
            destroy_cspace(child->root_cnode);
            kmem_cache_free(process_cache, child);
            return nullptr;
        }
    }

    if (unlikely(!capability_bootstrap_injection(
            parent,
            child,
            parent_proc_cap_id,
            parent_cnode_id,
            parent_vspace_id
        ))) {
        kref_put(&child->vspace->refcount, vmm_space_release);

        destroy_cspace(child->root_cnode);
        if (flags & CLONE_VM) pagemap_release(child->map);
        kmem_cache_free(process_cache, child);
        return nullptr;
    }

    child->parent = parent;

    acquire_qspinlock(&global_process_lock);
    dlist_add_tail(&child->sibling_node, &parent->children_list);
    release_qspinlock(&global_process_lock);

    return child;
}

uint64_t process_wait(process_t* proc, int* exit_code) {
    if (unlikely(!proc)) return 0;

    wait_event(&proc->wait_queue, proc->state == PROCESS_ZOMBIE || proc->state == PROCESS_DEAD);

    acquire_qspinlock(&proc->lock);
    if (exit_code) *exit_code = proc->exit_code;
    proc->state = PROCESS_DEAD;
    release_qspinlock(&proc->lock);

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
    if (unlikely(!obj)) return;

    process_t* proc = kref_entry(obj, struct process, kobj);
    posix_cleanup_all_children(proc);
    wait_queue_wake_up_all(&proc->vfork_wait_queue);

    if (proc->vspace && !proc->is_kernel) {
        kref_put(&proc->vspace->refcount, vmm_space_release);
        pagemap_release(proc->map);
    }

    acquire_qspinlock(&global_process_lock);
    acquire_qspinlock(&proc->lock);

    while (!dlist_empty(&proc->children_list)) {
        struct dlist_head* node = proc->children_list.next;
        struct process* orphan  = dlist_entry(node, struct process, sibling_node);

        dlist_del(node);

        if (likely(init_process)) {
            orphan->parent = init_process;
            dlist_add_tail(&orphan->sibling_node, &init_process->children_list);
        }
    }

    if (!dlist_empty(&proc->sibling_node)) dlist_del_init(&proc->sibling_node);
    process_t* parent = proc->parent;

    release_qspinlock(&proc->lock);
    release_qspinlock(&global_process_lock);

    if (parent) wait_queue_wake_up_all(&parent->wait_queue);

    destroy_cspace(proc->root_cnode);
    pagemap_release(proc->map);
    kmem_cache_free(process_cache, proc);
}