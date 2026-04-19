#include <stdint.h>
#include <string.h>

#include "compiler.h"
#include "core/capability.h"
#include "core/errors.h"
#include "core/syscalls.h"
#include "cpu/smp.h"
#include "libs/kobject.h"
#include "memory/vma.h"
#include "sched/process.h"
#include "sched/scheduler.h"

static inline bool write_cap_out(uint64_t* ptr, uint64_t val) {
    if (!ptr) return true;

    if (!vmm_is_user_region((uintptr_t)ptr, sizeof(uint64_t))) return false;

    copy_to_user(ptr, &val, sizeof(uint64_t));
    return true;
}

int64_t sys_process_create(
    const char* user_name,
    uint64_t* out_proc_cap,
    uint64_t* out_cnode_cap,
    uint64_t* out_vspace_cap
) {
    char name[32] = {0};
    if (user_name) {
        if (!vmm_is_user_region((uintptr_t)user_name, 1)) return ERR_FAULT;
        strncpy(name, user_name, sizeof(name) - 1);
    } else {
        strcpy(name, "user_proc");
    }

    struct vm_space* new_vspace = vmm_create_space(false);
    if (!new_vspace) return ERR_NO_MEM;

    int error           = ERR_OK;
    process_t* new_proc = process_create(name, false, new_vspace, &error);
    if (!new_proc) {
        vmm_space_release(&new_vspace->refcount);
        return error;
    }

    thread_t* curr             = smp_current_core()->curr_thread;
    struct cnode* parent_croot = curr->owner->root_cnode;

    uint64_t p_cap, c_cap, v_cap;

    struct capability* p_slot = cap_alloc(parent_croot, &p_cap);
    struct capability* c_slot = cap_alloc(parent_croot, &c_cap);
    struct capability* v_slot = cap_alloc(parent_croot, &v_cap);

    if (unlikely(!p_slot || !c_slot || !v_slot)) {
        if (p_slot) cap_close(parent_croot, p_cap);
        if (c_slot) cap_close(parent_croot, c_cap);
        if (v_slot) cap_close(parent_croot, v_cap);
        kref_put(&new_proc->kobj, process_release);
        return -ERR_CAP_EXHAUSTED;
    }

    // Populate Process Capability
    acquire_qspinlock(&p_slot->lock);
    p_slot->type   = CAP_TYPE_PROCESS;
    p_slot->rights = RIGHT_ALL & ~RIGHT_CLOEXEC;
    kref_get(&new_proc->kobj);
    atomic_store_explicit(&p_slot->object_ptr, (uintptr_t)new_proc, memory_order_release);
    release_qspinlock(&p_slot->lock);

    // Populate CNode Capability
    acquire_qspinlock(&c_slot->lock);
    c_slot->type   = CAP_TYPE_CNODE;
    c_slot->rights = RIGHT_ALL & ~RIGHT_CLOEXEC;
    atomic_store_explicit(
        &c_slot->object_ptr,
        (uintptr_t)new_proc->root_cnode,
        memory_order_release
    );
    release_qspinlock(&c_slot->lock);

    // Populate VSpace Capability
    acquire_qspinlock(&v_slot->lock);
    v_slot->type   = CAP_TYPE_VSPACE;
    v_slot->rights = RIGHT_ALL & ~RIGHT_CLOEXEC;
    kref_get(&new_proc->vspace->refcount);
    atomic_store_explicit(&v_slot->object_ptr, (uintptr_t)new_proc->vspace, memory_order_release);
    release_qspinlock(&v_slot->lock);

    if (!write_cap_out(out_proc_cap, p_cap) || !write_cap_out(out_cnode_cap, c_cap) ||
        !write_cap_out(out_vspace_cap, v_cap)) {
        cap_close(parent_croot, p_cap);
        cap_close(parent_croot, c_cap);
        cap_close(parent_croot, v_cap);
        kref_put(&new_proc->kobj, process_release);
        return ERR_FAULT;
    }

    return ERR_OK;
}

int64_t sys_thread_spawn(
    uint64_t target_proc_cap,
    uint64_t target_vspace_cap,
    uintptr_t entry_rip,
    uintptr_t stack_rsp,
    uint64_t arg1,
    uint64_t* out_thread_cap
) {
    thread_t* curr      = smp_current_core()->curr_thread;
    struct cnode* croot = curr->owner->root_cnode;

    struct capability* p_cap = cap_lookup(croot, target_proc_cap, RIGHT_WRITE);
    if (unlikely(!p_cap || p_cap->type != CAP_TYPE_PROCESS)) return ERR_INVALID_CAP;

    struct capability* v_cap = cap_lookup(croot, target_vspace_cap, RIGHT_READ);
    if (unlikely(!v_cap || v_cap->type != CAP_TYPE_VSPACE)) return ERR_INVALID_CAP;

    process_t* target_proc =
        (process_t*)atomic_load_explicit(&p_cap->object_ptr, memory_order_acquire);
    struct vm_space* target_vspace =
        (struct vm_space*)atomic_load_explicit(&v_cap->object_ptr, memory_order_acquire);

    if (unlikely(!target_proc || !target_vspace || target_proc->state != PROCESS_ALIVE))
        return ERR_SRCH;

    if (unlikely(target_proc->vspace != target_vspace)) return ERR_INVALID;

    int err              = ERR_OK;
    thread_t* new_thread = thread_create(
        "user_thread",
        target_proc,
        target_vspace,
        SCHED_NORMAL,
        entry_rip,
        arg1,
        stack_rsp,
        &err,
        0
    );

    if (unlikely(!new_thread)) return err;

    uint64_t t_cap_id        = 0;
    struct capability* t_cap = cap_alloc(croot, &t_cap_id);
    if (unlikely(!t_cap)) {
        kref_put(&new_thread->kobj, thread_release);
        return ERR_CAP_EXHAUSTED;
    }

    acquire_qspinlock(&t_cap->lock);
    t_cap->badge  = 0;
    t_cap->type   = CAP_TYPE_THREAD;
    t_cap->rights = RIGHT_ALL & ~RIGHT_CLOEXEC;
    kref_get(&new_thread->kobj);
    atomic_store_explicit(&t_cap->object_ptr, (uintptr_t)new_thread, memory_order_release);
    atomic_init(&t_cap->generation, 1);
    release_qspinlock(&t_cap->lock);

    if (out_thread_cap) {
        if (!write_cap_out(out_thread_cap, t_cap_id)) {
            cap_close(croot, t_cap_id);
            kref_put(&new_thread->kobj, thread_release);
            return ERR_FAULT;
        }
    }

    scheduler_add_thread(new_thread);
    kref_put(&new_thread->kobj, thread_release);

    return ERR_OK;
}

int64_t sys_clone(
    uint64_t flags,
    uintptr_t child_rsp_override,
    uintptr_t child_rip_override,
    struct syscall_regs* regs,
    uint64_t* out_proc_cap,
    uint64_t* out_thread_cap,
    uint64_t* out_cnode_cap,
    uint64_t* out_vspace_cap
) {
    thread_t* curr         = smp_current_core()->curr_thread;
    process_t* target_proc = curr->owner;
    struct cnode* croot    = target_proc->root_cnode;

    uint64_t p_cap = 0, c_cap = 0, v_cap = 0, t_cap = 0;

    int error = 0;
    if (!(flags & CLONE_INTO_CURRENT_PROCESS)) {
        target_proc = process_clone(curr->owner, flags, &error);
        if (unlikely(!target_proc)) return error;
    }

    thread_t* child_thread =
        thread_clone(target_proc, curr, regs, child_rsp_override, child_rip_override, &error);
    if (unlikely(!child_thread)) {
        if (!(flags & CLONE_INTO_CURRENT_PROCESS)) kref_put(&target_proc->kobj, process_release);
        return ERR_NO_MEM;
    }

    bool cap_error = 0;

    struct capability* t_slot = cap_alloc(croot, &t_cap);
    if (!t_slot) cap_error = true;

    struct capability* p_slot = nullptr;
    struct capability* c_slot = nullptr;
    struct capability* v_slot = nullptr;

    if (!(flags & CLONE_INTO_CURRENT_PROCESS) && !cap_error) {
        p_slot = cap_alloc(croot, &p_cap);
        c_slot = cap_alloc(croot, &c_cap);
        v_slot = cap_alloc(croot, &v_cap);

        if (!p_slot || !c_slot || !v_slot) cap_error = true;
    }

    if (unlikely(cap_error)) {
        if (t_slot) cap_close(croot, t_cap);
        if (p_slot) cap_close(croot, p_cap);
        if (c_slot) cap_close(croot, c_cap);
        if (v_slot) cap_close(croot, v_cap);

        kref_put(&child_thread->kobj, thread_release);
        if (!(flags & CLONE_INTO_CURRENT_PROCESS)) kref_put(&target_proc->kobj, process_release);

        return ERR_CAP_EXHAUSTED;
    }

    acquire_qspinlock(&t_slot->lock);
    t_slot->type   = CAP_TYPE_THREAD;
    t_slot->rights = RIGHT_ALL & ~RIGHT_CLOEXEC;
    kref_get(&child_thread->kobj);
    atomic_store_explicit(&t_slot->object_ptr, (uintptr_t)child_thread, memory_order_release);
    release_qspinlock(&t_slot->lock);

    if (!(flags & CLONE_INTO_CURRENT_PROCESS)) {
        acquire_qspinlock(&p_slot->lock);
        p_slot->type   = CAP_TYPE_PROCESS;
        p_slot->rights = RIGHT_ALL & ~RIGHT_CLOEXEC;
        kref_get(&target_proc->kobj);
        atomic_store_explicit(&p_slot->object_ptr, (uintptr_t)target_proc, memory_order_release);
        release_qspinlock(&p_slot->lock);

        acquire_qspinlock(&c_slot->lock);
        c_slot->type   = CAP_TYPE_CNODE;
        c_slot->rights = RIGHT_ALL & ~RIGHT_CLOEXEC;
        atomic_store_explicit(
            &c_slot->object_ptr,
            (uintptr_t)target_proc->root_cnode,
            memory_order_release
        );
        release_qspinlock(&c_slot->lock);

        acquire_qspinlock(&v_slot->lock);
        v_slot->type   = CAP_TYPE_VSPACE;
        v_slot->rights = RIGHT_ALL & ~RIGHT_CLOEXEC;
        kref_get(&target_proc->vspace->refcount);
        atomic_store_explicit(
            &v_slot->object_ptr,
            (uintptr_t)target_proc->vspace,
            memory_order_release
        );
        release_qspinlock(&v_slot->lock);
    }

    bool export_ok = true;
    export_ok &= write_cap_out(out_thread_cap, t_cap);

    if (!(flags & CLONE_INTO_CURRENT_PROCESS)) {
        export_ok &= write_cap_out(out_proc_cap, p_cap);
        export_ok &= write_cap_out(out_cnode_cap, c_cap);
        export_ok &= write_cap_out(out_vspace_cap, v_cap);
    }

    if (unlikely(!export_ok)) {
        cap_close(croot, t_cap);
        kref_put(&child_thread->kobj, thread_release);

        if (!(flags & CLONE_INTO_CURRENT_PROCESS)) {
            target_proc->state = PROCESS_DEAD;
            cap_close(croot, p_cap);
            cap_close(croot, c_cap);
            cap_close(croot, v_cap);
            kref_put(&target_proc->kobj, process_release);
        }

        return ERR_FAULT;
    }

    if (!(flags & CLONE_SUSPENDED)) scheduler_add_thread(child_thread);
    if (flags & CLONE_VFORK) scheduler_yield();

    kref_put(&child_thread->kobj, thread_release);
    if (!(flags & CLONE_INTO_CURRENT_PROCESS)) kref_put(&target_proc->kobj, process_release);

    return ERR_OK;
}

void sys_sched_yield(void) {
    scheduler_yield();
}

#define NS_PER_MS 1000000ul

int64_t sys_thread_sleep(uint64_t ns) {
    uint64_t ms = ns / NS_PER_MS;
    if (ms == 0) ms = 1;
    return scheduler_sleep((int64_t)ms);
}