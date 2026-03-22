#ifndef KERNEL_SCHED_SYSCALLS_H
#define KERNEL_SCHED_SYSCALLS_H 1

#include <stddef.h>
#include <stdint.h>

#include "cpu/exception.h"
#include "cpu/syscalls.h"

#ifdef __cplusplus
extern "C" {
#endif

#define SYS_WRITE    0x01
#define SYS_MMAP     0x09
#define SYS_MPROTECT 0x0a
#define SYS_MUNMAP   0x0b
#define SYS_MREMAP   0x19
#define SYS_CLONE    0x38
#define SYS_FORK     0x39
#define SYS_VFORK    0x3a
#define SYS_EXIT     0x3c

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

size_t copy_from_user(void* dest, const void* src, size_t len);
size_t copy_to_user(void* dest, const void* src, size_t len);

void syscalls_init(void);
int64_t sys_write(uint32_t fd, const char* user_buf, size_t count);
int sys_fork(syscall_regs_t* tf);
int sys_vfork(syscall_regs_t* tf);
int sys_clone(uint64_t flags, void* child_stack, syscall_regs_t* tf);
int sys_execv(const char* path, const char* argv[], syscall_regs_t* tf);

#ifdef __cplusplus
}
#endif

#endif