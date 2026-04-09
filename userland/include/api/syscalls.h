#ifndef USERLAND_SYSCALLS_H
#define USERLAND_SYSCALLS_H 1

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SYS_CATEGORY_SCHED 0x0300

#define SYS_SCHED_SPAWN_PROCESS (SYS_CATEGORY_SCHED | 0x01)
#define SYS_SCHED_SPAWN_THREAD  (SYS_CATEGORY_SCHED | 0x02)
#define SYS_SCHED_CLONE         (SYS_CATEGORY_SCHED | 0x03)
#define SYS_SCHED_YIELD         (SYS_CATEGORY_SCHED | 0x04)
#define SYS_SCHED_SLEEP         (SYS_CATEGORY_SCHED | 0x05)

#define SYS_WRITE    0x01
#define SYS_MMAP     0x09
#define SYS_MPROTECT 0x0a
#define SYS_MUNMAP   0x0b
#define SYS_MREMAP   0x19
#define SYS_CLONE    0x38
#define SYS_VFORK    0x3a

// Creates a new thread inside the caller's process, otherwise create a new process
#define CLONE_INTO_CURRENT_PROCESS (1 << 0)
// Child shares the parent's vspace otherise perform a deep-copy (CoW) of the VSpace
#define CLONE_SHARE_VSPACE (1 << 1)
// The kernel deep-copies the parent's CNode tree to the child.
#define CLONE_COPY_CSPACE (1 << 2)
// The new thread is created in THREAD_SUSPENDED state, the paent must explicityl start it via IPC
#define CLONE_SUSPENDED (1 << 3)
// The parent thread yields the CPU immediately so the child can run.
#define CLONE_VFORK (1 << 4)

int64_t write(int fd, const char* str, size_t len);

int64_t process_create(
    const char* name,
    uint64_t* out_proc_cap,
    uint64_t* out_cnode_cap,
    uint64_t* out_vspace_cap
);

int64_t thread_spawn(
    uint64_t target_proc_cap,
    uint64_t target_vspace_cap,
    uintptr_t entry_rip,
    uintptr_t stack_rsp,
    uint64_t arg1,
    uint64_t* out_thread_cap
);

int64_t clone(
    uint64_t flags,
    uintptr_t child_rsp_override,
    uintptr_t child_rip_override,
    uint64_t* out_proc_cap,
    uint64_t* out_thread_cap,
    uint64_t* out_cnode_cap,
    uint64_t* out_vspace_cap
);

void yield(void);
int64_t thread_sleep(uint64_t ns);

#ifdef __cplusplus
}
#endif

#endif