#include "cpu/syscalls.h"

#include <errno.h>
#include <stdint.h>

#include "libs/log.h"
#include "sched/process.h"
#include "sched/sched_class.h"
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

uint64_t sys_fork(struct syscall_regs* tf) {
    per_cpu_data_t* cpu = smp_current_core();
    thread_t* parent    = cpu->curr_thread;
    uint64_t parent_cap_id, parent_cnode_id;

    process_t* child_proc = process_clone(parent->owner, 0, &parent_cap_id, &parent_cnode_id);
    if (!child_proc) {
        return 0;
    }

    thread_t* child_thread = thread_clone(child_proc, parent, tf, nullptr);
    if (!child_thread) {
        kref_put(&child_proc->kobj, process_release);
        return 0;
    }

    scheduler_add_thread(child_thread);
    scheduler_yield();

    return child_proc->kobj.koid;
}

uint64_t sys_vfork(struct syscall_regs* tf) {
    per_cpu_data_t* cpu = smp_current_core();
    thread_t* parent    = cpu->curr_thread;

    uint64_t parent_cap_id, parent_cnode_id;
    return thread_vclone(parent, tf, &parent_cap_id, &parent_cnode_id);
}

uint64_t sys_clone(uint64_t flags, void* child_stack, struct syscall_regs* tf) {
    per_cpu_data_t* cpu     = smp_current_core();
    thread_t* parent_thread = cpu->curr_thread;
    process_t* target_proc  = parent_thread->owner;
    uint64_t parent_cap_id, parent_cnode_id;

    if (!(flags & CLONE_THREAD)) {
        target_proc = process_clone(parent_thread->owner, flags, &parent_cap_id, &parent_cnode_id);
        if (!target_proc) {
            return 0;
        }
    }

    thread_t* child_thread = thread_clone(target_proc, parent_thread, tf, child_stack);
    if (!child_stack) {
        if (!(flags & CLONE_THREAD)) {
            kref_put(&target_proc->kobj, process_release);
        }

        return 0;
    }

    scheduler_add_thread(child_thread);
    return (flags & CLONE_THREAD) ? child_thread->kobj.koid : target_proc->kobj.koid;
}