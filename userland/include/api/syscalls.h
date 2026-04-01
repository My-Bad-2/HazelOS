#ifndef USERLAND_SYSCALLS_H
#define USERLAND_SYSCALLS_H 1

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SYS_CATEGORY_SCHED 0x0300

#define SYS_SCHED_FORK (SYS_CATEGORY_SCHED | 0x01)

#define SYS_WRITE    0x01
#define SYS_MMAP     0x09
#define SYS_MPROTECT 0x0a
#define SYS_MUNMAP   0x0b
#define SYS_MREMAP   0x19
#define SYS_CLONE    0x38
#define SYS_VFORK    0x3a
#define SYS_EXIT     0x3c

int64_t write(int fd, const char* str, size_t len);
uint64_t fork(void);
void exit(int exit_code);

#ifdef __cplusplus
}
#endif

#endif