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
        return EINVAL;
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

int sys_fork(syscall_regs_t* tf) {
    per_cpu_data_t* cpu = smp_current_core();
    thread_t* parent    = cpu->curr_thread;

    process_t* child_proc = process_clone(parent->owner, 0);
    if (!child_proc) {
        return -ENOMEM;
    }

    thread_t* child_thread = thread_clone(child_proc, parent, tf, nullptr);
    if (!child_thread) {
        process_destroy(child_proc);
        return -ENOMEM;
    }

    scheduler_add_thread(child_thread);
    scheduler_yield();

    return child_proc->pid;
}

int sys_vfork(syscall_regs_t* tf) {
    per_cpu_data_t* cpu = smp_current_core();
    thread_t* parent    = cpu->curr_thread;

    return thread_vclone(parent, tf);
}

int sys_clone(uint64_t flags, void* child_stack, syscall_regs_t* tf) {
    per_cpu_data_t* cpu     = smp_current_core();
    thread_t* parent_thread = cpu->curr_thread;
    process_t* target_proc  = parent_thread->owner;

    if (!(flags & CLONE_THREAD)) {
        target_proc = process_clone(parent_thread->owner, flags);
        if (!target_proc) {
            return -ENOMEM;
        }
    }

    thread_t* child_thread = thread_clone(target_proc, parent_thread, tf, child_stack);
    if (!child_stack) {
        if (!(flags & CLONE_THREAD)) {
            process_destroy(target_proc);
        }

        return -ENOMEM;
    }

    scheduler_add_thread(child_thread);
    return (flags & CLONE_THREAD) ? child_thread->tid : target_proc->pid;
}