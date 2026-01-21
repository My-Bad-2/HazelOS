#ifndef USERLAND_SYSCALLS_H
#define USERLAND_SYSCALLS_H 1

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SYS_WRITE 1

static inline int64_t syscall3(uint64_t id, uint64_t arg1, uint64_t arg2, uint64_t arg3) {
    int64_t ret = 0;

    asm volatile("syscall"
                 : "=a"(ret)
                 : "a"(id), "D"(arg1), "S"(arg2), "d"(arg3)
                 : "rcx", "r11", "memory");
    return ret;
}

static inline int64_t write(int fd, const char* str, size_t len) {
    return syscall3(SYS_WRITE, (uint64_t)fd, (uintptr_t)str, len);
}

#ifdef __cplusplus
}
#endif

#endif