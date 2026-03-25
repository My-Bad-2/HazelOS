#include "api/syscalls.h"

#include <stddef.h>
#include <stdint.h>

#include "syscall.h"

#define TIMER_FLAG_PERIODIC (1 << 0)

int64_t write(int fd, const char* str, size_t len) {
    return syscall(SYS_WRITE, (long)fd, (long)str, (long)len);
}

void* mmap(void* addr, size_t length, int prot, int flags, int fd, off_t offset) {
    return (void*)syscall(SYS_MMAP, (long)addr, (long)length, prot, flags, fd, offset);
}

int mprotect(void* addr, size_t length, int prot) {
    return (int)syscall(SYS_MPROTECT, (long)addr, (long)length, prot);
}

int munmmap(void* addr, size_t length) {
    return (int)syscall(SYS_MUNMAP, (long)addr, (long)length);
}

int fork(void) {
    return syscall(SYS_FORK, 0);
}