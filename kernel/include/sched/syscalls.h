#ifndef KERNEL_SCHED_SYSCALLS_H
#define KERNEL_SCHED_SYSCALLS_H 1

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SYS_WRITE 1

#define STDOUT_FILENO 1
#define STDERR_FILENO 2

bool copy_from_user(void* dest, const void* src, size_t len);
void syscalls_init(void);

int64_t sys_write(uint32_t fd, const char* user_buf, size_t count);

#ifdef __cplusplus
}
#endif

#endif