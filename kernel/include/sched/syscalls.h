#ifndef KERNEL_SCHED_SYSCALLS_H
#define KERNEL_SCHED_SYSCALLS_H 1

#include <stddef.h>
#include <stdint.h>

#include "cpu/syscalls.h"

#ifdef __cplusplus
extern "C" {
#endif

#define SYS_CATEGORY_CAP   0x0100
#define SYS_CATEGORY_IPC   0x0200
#define SYS_CATEGORY_SCHED 0x0300
#define SYS_CATEGORY_MEM   0x0400

#define SYS_CAP_DELEGATE (SYS_CATEGORY_CAP | 0x01)  // Grant a capability to another CNode
#define SYS_CAP_CLOSE    (SYS_CATEGORY_CAP | 0x02)  // Close a cap
#define SYS_CAP_COPY     (SYS_CATEGORY_CAP | 0x03)  // Duplicate a cap within the same CNode
#define SYS_CAP_MINT     (SYS_CATEGORY_CAP | 0x04)  // Copy a cap but downgrade its rights
#define SYS_CAP_ALIAS    (SYS_CATEGORY_CAP | 0x05)

#define SYS_IPC_CHANNEL_CREATE      (SYS_CATEGORY_IPC | 0x01)
#define SYS_IPC_PORT_CREATE         (SYS_CATEGORY_IPC | 0x02)
#define SYS_IPC_BIND                (SYS_CATEGORY_IPC | 0x03)
#define SYS_IPC_CALL                (SYS_CATEGORY_IPC | 0x04)
#define SYS_IPC_WAIT                (SYS_CATEGORY_IPC | 0x05)
#define SYS_IPC_SEND                (SYS_CATEGORY_IPC | 0x06)
#define SYS_IPC_RECV                (SYS_CATEGORY_IPC | 0x07)
#define SYS_IPC_NOTIFICATION_CREATE (SYS_CATEGORY_IPC | 0x08)
#define SYS_IPC_NOTIFY              (SYS_CATEGORY_IPC | 0x09)

#define SYS_SCHED_FORK (SYS_CATEGORY_SCHED | 0x01)
#define SYS_SCHED_EXIT (SYS_CATEGORY_SCHED | 0x02)

#define SYS_MEM_MMAP            (SYS_CATEGORY_MEM | 0x01)
#define SYS_MEM_MUNMAP          (SYS_CATEGORY_MEM | 0x02)
#define SYS_MEM_MREMAP          (SYS_CATEGORY_MEM | 0x03)
#define SYS_MEM_MPROTECT        (SYS_CATEGORY_MEM | 0x04)
#define SYS_MEM_VSPACE_MMAP     (SYS_CATEGORY_MEM | 0x05)
#define SYS_MEM_VSPACE_MUNMAP   (SYS_CATEGORY_MEM | 0x06)
#define SYS_MEM_VSPACE_MREMAP   (SYS_CATEGORY_MEM | 0x07)
#define SYS_MEM_VSPACE_MPROTECT (SYS_CATEGORY_MEM | 0x08)

#define SYS_WRITE 0x01
#define SYS_CLONE 0x38
#define SYS_FORK  0x39
#define SYS_VFORK 0x3a
#define SYS_EXIT  0x3c

#define STDOUT_FILENO 1
#define STDERR_FILENO 2

size_t copy_from_user(void* dest, const void* src, size_t len);
size_t copy_to_user(void* dest, const void* src, size_t len);

void syscalls_init(void);
int64_t sys_write(uint32_t fd, const char* user_buf, size_t count);

int64_t sys_cap_clone(
    uint64_t flags,
    void* child_stack,
    struct syscall_regs* regs,
    uint64_t* out_proc_cap,
    uint64_t* out_thread_cap,
    uint64_t* out_cnode_cap,
    uint64_t* out_vspace_cap
);

int64_t sys_fork(struct syscall_regs* tf);
void sys_exit(int exit_code);
uint64_t sys_vfork(struct syscall_regs* tf);
int64_t sys_clone(uint64_t flags, void* child_stack, struct syscall_regs* tf);
int sys_waitpid(int64_t pid, int* status, int options);

#ifdef __cplusplus
}
#endif

#endif