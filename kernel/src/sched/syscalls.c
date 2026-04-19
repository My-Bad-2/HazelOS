#include "core/syscalls.h"

#include <stdatomic.h>
#include <stdint.h>

#include "core/errors.h"
#include "libs/log.h"
#include "sched/process.h"

extern void arch_syscalls_init(void);

void syscalls_init(void) {
    arch_syscalls_init();
}

int64_t sys_write(uint32_t fd, const char* user_buf, size_t count) {
    if (count == 0) {
        return 0;
    }

    if (count > (1ul << 31)) {
        return ERR_INVALID;
    }

    char buf[256];
    size_t bytes_processed = 0;

    while (bytes_processed < count) {
        size_t chunk_size = count - bytes_processed;

        if (chunk_size > sizeof(buf) - 1) {
            chunk_size = sizeof(buf) - 1;
        }

        if (copy_from_user(buf, user_buf + bytes_processed, chunk_size) > 0) {
            return ERR_FAULT;
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