#ifndef KERNEL_SCHED_SYSCALLS_H
#define KERNEL_SCHED_SYSCALLS_H 1

#include <stddef.h>
#include <stdint.h>

#include "cpu/syscalls.h"

#ifdef __cplusplus
extern "C" {
#endif

// Syscall Category
#define SYS_CATEGORY_CAP   0x0100
#define SYS_CATEGORY_IPC   0x0200
#define SYS_CATEGORY_SCHED 0x0300
#define SYS_CATEGORY_MEM   0x0400

// Capability syscalls
#define SYS_CAP_DELEGATE (SYS_CATEGORY_CAP | 0x01)  // Grant a capability to another CNode
#define SYS_CAP_CLOSE    (SYS_CATEGORY_CAP | 0x02)  // Close a cap
#define SYS_CAP_COPY     (SYS_CATEGORY_CAP | 0x03)  // Duplicate a cap within the same CNode
#define SYS_CAP_MINT     (SYS_CATEGORY_CAP | 0x04)  // Copy a cap but downgrade its rights
#define SYS_CAP_ALIAS    (SYS_CATEGORY_CAP | 0x05)

// IPC syscalls
#define SYS_IPC_CHANNEL_CREATE      (SYS_CATEGORY_IPC | 0x01)
#define SYS_IPC_PORT_CREATE         (SYS_CATEGORY_IPC | 0x02)
#define SYS_IPC_BIND                (SYS_CATEGORY_IPC | 0x03)
#define SYS_IPC_CALL                (SYS_CATEGORY_IPC | 0x04)
#define SYS_IPC_WAIT                (SYS_CATEGORY_IPC | 0x05)
#define SYS_IPC_SEND                (SYS_CATEGORY_IPC | 0x06)
#define SYS_IPC_RECV                (SYS_CATEGORY_IPC | 0x07)
#define SYS_IPC_NOTIFICATION_CREATE (SYS_CATEGORY_IPC | 0x08)
#define SYS_IPC_NOTIFY              (SYS_CATEGORY_IPC | 0x09)

// Scheduling/Thread/Process syscalls
#define SYS_SCHED_SPAWN_PROCESS (SYS_CATEGORY_SCHED | 0x01)
#define SYS_SCHED_SPAWN_THREAD  (SYS_CATEGORY_SCHED | 0x02)
#define SYS_SCHED_CLONE         (SYS_CATEGORY_SCHED | 0x03)
#define SYS_SCHED_YIELD         (SYS_CATEGORY_SCHED | 0x04)
#define SYS_SCHED_SLEEP         (SYS_CATEGORY_SCHED | 0x05)

// VSpace Syscalls
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

#define STDOUT_FILENO 1
#define STDERR_FILENO 2

#define OPTION_WAIT_NOHANG 1

size_t copy_from_user(void* dest, const void* src, size_t len);
size_t copy_to_user(void* dest, const void* src, size_t len);

void syscalls_init(void);
int64_t sys_write(uint32_t fd, const char* user_buf, size_t count);

int64_t sys_fork(struct syscall_regs* tf);
void sys_exit(int exit_code);

// --- Scheduling Category ---
struct clone_args {
    uint64_t* out_proc_cap;
    uint64_t* out_cnode_cap;
    uint64_t* out_vspace_cap;
    uint64_t* out_thread_cap;
};

int64_t sys_process_create(
    const char* name,
    uint64_t* out_proc_cap,
    uint64_t* out_cnode_cap,
    uint64_t* out_vspace_cap
);

int64_t sys_thread_spawn(
    uint64_t target_proc_cap,
    uint64_t target_vspace_cap,
    uintptr_t entry_rip,
    uintptr_t stack_rsp,
    uint64_t arg1,
    uint64_t* out_thread_cap
);

int64_t sys_clone(
    uint64_t flags,
    uintptr_t child_rsp_override,
    uintptr_t child_rip_override,
    struct syscall_regs* regs,
    uint64_t* out_proc_cap,
    uint64_t* out_thread_cap,
    uint64_t* out_cnode_cap,
    uint64_t* out_vspace_cap
);

void sys_sched_yield(void);
int64_t sys_thread_sleep(uint64_t ns);

[[noreturn]] void thread_exit(int exit_code);
[[noreturn]] void thread_exit(int exit_code);

#ifdef __cplusplus
}
#endif

#endif