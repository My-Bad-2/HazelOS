#include "api/syscalls.h"

#include <stddef.h>
#include <stdint.h>

#include "syscall.h"

#define TIMER_FLAG_PERIODIC (1 << 0)

int64_t write(int fd, const char* str, size_t len) {
    return syscall(SYS_WRITE, (long)fd, (long)str, (long)len);
}

uint64_t fork(void) {
    return (uint64_t)syscall(SYS_SCHED_FORK, 0);
}

void exit(int exit_code) {
    syscall(SYS_SCHED_EXIT, exit_code);
}