#include "cpu/syscalls.h"

#include <errno.h>
#include <stdatomic.h>
#include <stdint.h>

#include "compiler.h"
#include "core/capability.h"
#include "core/errors.h"
#include "core/posix_emul.h"
#include "cpu/smp.h"
#include "libs/log.h"
#include "memory/vma.h"
#include "sched/process.h"
#include "sched/scheduler.h"
#include "sched/syscalls.h"

extern void arch_syscalls_init(void);

void syscalls_init(void) {
    arch_syscalls_init();
}

int64_t sys_write(uint32_t fd, const char* user_buf, size_t count) {
    if (count == 0) {
        return 0;
    }

    if (count > (1ul << 31)) {
        return -EINVAL;
    }

    char buf[256];
    size_t bytes_processed = 0;

    while (bytes_processed < count) {
        size_t chunk_size = count - bytes_processed;

        if (chunk_size > sizeof(buf) - 1) {
            chunk_size = sizeof(buf) - 1;
        }

        if (copy_from_user(buf, user_buf + bytes_processed, chunk_size) > 0) {
            return EFAULT;
        }

        if (fd == STDERR_FILENO) {
            KLOG_ERROR("%s", buf);
        } else {
            KLOG_INFO("%s", buf);
        }

        bytes_processed += chunk_size;
    }

    return (int64_t)bytes_processed;
}

int64_t sys_fork(struct syscall_regs* regs) {
    uint64_t proc_cap, cnode_cap, vspace_cap;

    int64_t err = sys_cap_clone(0, nullptr, regs, &proc_cap, nullptr, &cnode_cap, &vspace_cap);
    if (err < 0) return err;

    thread_t* curr = smp_current_core()->curr_thread;

    struct capability* cap = cap_lookup(curr->owner->root_cnode, proc_cap, RIGHT_READ);
    process_t* child_proc =
        (process_t*)atomic_load_explicit(&cap->object_ptr, memory_order_acquire);
    uint64_t child_koid = child_proc->kobj.koid;

    cap_close(curr->owner->root_cnode, cnode_cap);
    cap_close(curr->owner->root_cnode, vspace_cap);

    return (int64_t)child_koid;
}

uint64_t sys_vfork(struct syscall_regs* tf) {
    per_cpu_data_t* cpu = smp_current_core();
    thread_t* parent    = cpu->curr_thread;

    uint64_t parent_cap_id, parent_cnode_id, parent_vspace_id;
    return thread_vclone(parent, tf, &parent_cap_id, &parent_cnode_id, &parent_vspace_id);
}

int64_t sys_clone(uint64_t flags, void* child_stack, struct syscall_regs* regs) {
    uint64_t proc_cap = 0, thread_cap = 0, cnode_cap = 0, vspace_cap = 0;

    int64_t err =
        sys_cap_clone(flags, child_stack, regs, &proc_cap, &thread_cap, &cnode_cap, &vspace_cap);
    if (err < 0) return err;

    thread_t* curr      = smp_current_core()->curr_thread;
    struct cnode* croot = curr->owner->root_cnode;
    if (flags & CLONE_THREAD) {
        struct capability* tcap = cap_lookup(croot, thread_cap, RIGHT_READ);
        thread_t* child_thread =
            (thread_t*)atomic_load_explicit(&tcap->object_ptr, memory_order_acquire);

        uint64_t child_tid = child_thread->kobj.koid;

        // POSIX programs don't manage capability limits. We must close the thread capability
        // immediately to prevent CSpace memory leak.
        cap_close(croot, thread_cap);
        return (int64_t)child_tid;
    }

    struct capability* cap = cap_lookup(croot, proc_cap, RIGHT_READ);
    process_t* child_proc =
        (process_t*)atomic_load_explicit(&cap->object_ptr, memory_order_acquire);

    uint64_t child_pid = child_proc->kobj.koid;
    posix_register_child_emulation(curr->owner, child_pid, proc_cap);

    cap_close(croot, cnode_cap);
    cap_close(croot, vspace_cap);
    cap_close(croot, vspace_cap);

    return (int64_t)child_pid;
}

void sys_exit(int exit_code) {
    process_exit(exit_code);
}

static inline bool write_cap_out(uint64_t* ptr, uint64_t val) {
    if (!ptr) return true;

    if (vmm_is_user_region((uintptr_t)ptr, sizeof(uint64_t)))
        return copy_to_user(ptr, &val, sizeof(uint64_t));

    *ptr = val;
    return true;
}

int64_t sys_cap_clone(
    uint64_t flags,
    void* child_stack,
    struct syscall_regs* regs,
    uint64_t* out_proc_cap,
    uint64_t* out_thread_cap,
    uint64_t* out_cnode_cap,
    uint64_t* out_vspace_cap
) {
    per_cpu_data_t* cpu        = smp_current_core();
    thread_t* parent_thread    = cpu->curr_thread;
    process_t* target_proc     = parent_thread->owner;
    struct cnode* parent_croot = target_proc->root_cnode;

    uint64_t p_cap = 0, c_cap = 0, v_cap = 0, t_cap = 0;

    if (!(flags & CLONE_THREAD)) {
        target_proc = process_clone(parent_thread->owner, flags, &p_cap, &c_cap, &v_cap);
        if (unlikely(!target_proc)) return -ENOMEM;
    }

    thread_t* child_thread = thread_clone(target_proc, parent_thread, regs, child_stack);
    if (unlikely(!child_thread)) {
        if (!(flags & CLONE_THREAD)) {
            cap_close(parent_croot, p_cap);
            cap_close(parent_croot, c_cap);
            cap_close(parent_croot, v_cap);
            kref_put(&target_proc->kobj, process_release);
        }

        return -ENOMEM;
    }

    struct capability* t_slot = cap_alloc(parent_croot, &t_cap);
    if (unlikely(!t_slot)) {
        kref_put(&child_thread->kobj, thread_release);

        if (!(flags & CLONE_THREAD)) {
            cap_close(parent_croot, p_cap);
            cap_close(parent_croot, c_cap);
            cap_close(parent_croot, v_cap);
            kref_put(&target_proc->kobj, process_release);
        }

        return -ENOMEM;
    }

    acquire_qspinlock(&t_slot->lock);
    t_slot->type   = CAP_TYPE_THREAD;
    t_slot->rights = RIGHT_ALL;
    kref_get(&child_thread->kobj);
    atomic_store_explicit(&t_slot->object_ptr, (uintptr_t)child_thread, memory_order_release);
    release_qspinlock(&t_slot->lock);

    bool export_ok = true;

    if (!(flags & CLONE_THREAD)) {
        export_ok &= write_cap_out(out_proc_cap, p_cap);
        export_ok &= write_cap_out(out_cnode_cap, c_cap);
        export_ok &= write_cap_out(out_vspace_cap, v_cap);
    }

    export_ok &= write_cap_out(out_thread_cap, t_cap);

    if (unlikely(!export_ok)) {
        cap_close(parent_croot, t_cap);
        kref_put(&child_thread->kobj, thread_release);

        if (!(flags & CLONE_THREAD)) {
            target_proc->state = PROCESS_DEAD;
            cap_close(parent_croot, p_cap);
            cap_close(parent_croot, c_cap);
            cap_close(parent_croot, v_cap);
            kref_put(&target_proc->kobj, process_release);
        }

        return -EFAULT;
    }

    scheduler_add_thread(child_thread);
    if (flags & CLONE_VFORK) scheduler_yield();
    return ERR_OK;
}