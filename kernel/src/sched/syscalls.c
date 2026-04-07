#include "core/syscalls.h"

#include <errno.h>
#include <llvm-libc-macros/generic-error-number-macros.h>
#include <stdatomic.h>
#include <stdint.h>

#include "compiler.h"
#include "core/capability.h"
#include "core/errors.h"
#include "cpu/smp.h"
#include "cpu/syscalls.h"
#include "libs/log.h"
#include "libs/spinlock.h"
#include "memory/vma.h"
#include "sched/process.h"
#include "sched/scheduler.h"

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

void sys_exit(int exit_code) {
    process_exit(exit_code);
}