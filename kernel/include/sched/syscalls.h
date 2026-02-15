#ifndef KERNEL_SCHED_SYSCALLS_H
#define KERNEL_SCHED_SYSCALLS_H 1

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SYS_WRITE    1
#define SYS_MMAP     9
#define SYS_MPROTECT 10
#define SYS_MUNMAP   11
#define SYS_EXIT     60

#define SYS_IPC_CREATE_CHANNEL  500
#define SYS_IPC_CREATE_PORT_SET 501
#define SYS_IPC_BIND            502
#define SYS_IPC_NOTIFY          503
#define SYS_IPC_WAIT            504
#define SYS_HANDLE_CLOSE        505
#define SYS_IPC_SEND_HANDLES    506
#define SYS_IPC_RECV_HANDLES    507
#define SYS_TIMER_ARM           508
#define SYS_IPC_SHM_ALLOC       509

#define STDOUT_FILENO 1
#define STDERR_FILENO 2

bool copy_from_user(void* dest, const void* src, size_t len);
void syscalls_init(void);

int64_t sys_write(uint32_t fd, const char* user_buf, size_t count);

#ifdef __cplusplus
}
#endif

#endif