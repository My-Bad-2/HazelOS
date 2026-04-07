#include "sched/process.h"

#include <stdatomic.h>
#include <stdint.h>
#include <string.h>

#include "compiler.h"
#include "core/capability.h"
#include "core/errors.h"
#include "cpu/smp.h"
#include "libs/dlist.h"
#include "libs/handles.h"
#include "libs/kobject.h"
#include "libs/spinlock.h"
#include "memory/heap.h"
#include "memory/vma.h"
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

process_t*
process_create(const char* name, bool is_kernel, struct vm_space* vspace, int* error_code) {
    if (error_code) *error_code = ERR_OK;

    if (unlikely(!process_cache)) {
        process_cache = kmem_cache_create(
            "process_cache",
            sizeof(struct process),
            _Alignof(struct process),
            SLAB_NEVER_MERGE | SLAB_HWCACHE_ALIGN,
            nullptr
        );
    }

    process_t* proc = kmem_cache_alloc(process_cache);
    if (unlikely(!proc)) {
        if (error_code) *error_code = ERR_NO_MEM;
        return nullptr;
    }

    memset(proc, 0, sizeof(process_t));
    kref_init(&proc->kobj, CAP_TYPE_PROCESS);

    proc->state      = PROCESS_ALIVE;
    proc->is_kernel  = is_kernel;
    proc->root_cnode = create_cspace();
    proc->vspace     = vspace;

#if KERNEL_DEBUG
    if (likely(name)) strncpy(proc->name, name, sizeof(proc->name) - 1);
#else
    (void)name;
#endif

    create_qspinlock(&proc->lock);
    dlist_init(&proc->thread_list);
    dlist_init(&proc->children_list);
    dlist_init(&proc->sibling_node);

    wait_queue_init(&proc->wait_queue);
    wait_queue_init(&proc->vfork_wait_queue);

    return proc;
}

process_t* process_clone(process_t* parent, uint64_t flags, int* error_code) {
    if (error_code) *error_code = ERR_OK;

    if (unlikely(!parent)) {
        *error_code = ERR_INVALID;
        return nullptr;
    }

    struct vm_space* child_vspace = nullptr;

    if (flags & CLONE_SHARE_VSPACE) {
        child_vspace = parent->vspace;
        kref_get(&child_vspace->refcount);
    } else {
        child_vspace = vmm_create_space(false);

        if (!child_vspace || !vmm_clone_space(parent->vspace, child_vspace)) {
            if (child_vspace) vmm_space_release(&child_vspace->refcount);
            if (error_code) *error_code = ERR_NO_MEM;
            return nullptr;
        }
    }

    int error = 0;

    process_t* child = process_create(
#if KERNEL_DEBUG
        parent->name,
#else
        nullptr,
#endif
        false,
        child_vspace,
        &error
    );

    if (unlikely(!child)) {
        if (!(flags & CLONE_SHARE_VSPACE)) vmm_space_release(&child_vspace->refcount);
        if (error_code) *error_code = error;
        return nullptr;
    }

    if (flags & CLONE_COPY_CSPACE) {
        // Deep copy the CNode tree, allowing the child to access the parent's IPC channels
        child->root_cnode = cnode_clone(parent->root_cnode);
        if (!child->root_cnode) {
            kref_put(&child->kobj, process_release);
            if (error_code) *error_code = ERR_NO_MEM;
            return nullptr;
        }
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
    proc->state       = PROCESS_ZOMBIE;
    proc->exit_code   = exit_code;
    process_t* parent = proc->parent;
    release_qspinlock(&proc->lock);

    wait_queue_wake_up_all(&proc->wait_queue);
    thread_exit(exit_code);
}

void process_release(struct kobject* obj) {
    if (unlikely(!obj)) return;

    process_t* proc = kref_entry(obj, struct process, kobj);
    wait_queue_wake_up_all(&proc->vfork_wait_queue);

    if (proc->vspace && !proc->is_kernel) {
        kref_put(&proc->vspace->refcount, vmm_space_release);
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
    kmem_cache_free(process_cache, proc);
}