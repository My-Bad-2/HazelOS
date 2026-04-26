#include "api/syscalls.h"

#include <stddef.h>
#include <stdint.h>

#include "syscall.h"

#define TIMER_FLAG_PERIODIC (1 << 0)

int64_t write(int fd, const char* str, size_t len) {
    return syscall(SYS_WRITE, (long)fd, (long)str, (long)len);
}

int64_t process_create(
    const char* name,
    uint64_t* out_proc_cap,
    uint64_t* out_cnode_cap,
    uint64_t* out_vspace_cap
) {
    return syscall(
        SYS_SCHED_SPAWN_PROCESS,
        (long)name,
        (long)out_proc_cap,
        (long)out_cnode_cap,
        (long)out_vspace_cap
    );
}

int64_t thread_spawn(
    uint64_t target_proc_cap,
    uint64_t target_vspace_cap,
    uintptr_t entry_rip,
    uintptr_t stack_rsp,
    uint64_t arg1,
    uint64_t* out_thread_cap
) {
    return syscall(
        SYS_SCHED_SPAWN_THREAD,
        (long)target_proc_cap,
        (long)target_vspace_cap,
        (long)entry_rip,
        (long)stack_rsp,
        (long)arg1,
        (long)out_thread_cap
    );
}

struct clone_args {
    uint64_t* out_proc_cap;
    uint64_t* out_cnode_cap;
    uint64_t* out_vspace_cap;
    uint64_t* out_thread_cap;
};

int64_t clone(
    uint64_t flags,
    uintptr_t child_rsp_override,
    uintptr_t child_rip_override,
    uint64_t* out_proc_cap,
    uint64_t* out_thread_cap,
    uint64_t* out_cnode_cap,
    uint64_t* out_vspace_cap
) {
    struct clone_args args = {
        .out_proc_cap   = out_proc_cap,
        .out_cnode_cap  = out_cnode_cap,
        .out_vspace_cap = out_vspace_cap,
        .out_thread_cap = out_thread_cap
    };

    return syscall(
        SYS_SCHED_CLONE,
        (long)flags,
        (long)child_rsp_override,
        (long)child_rip_override,
        (long)&args
    );
}

void yield(void) {
    syscall(SYS_SCHED_YIELD, 0);
}

int64_t thread_sleep(uint64_t ns) {
    return syscall(SYS_SCHED_SLEEP, (long)ns);
}

void thread_exit(int exit_code) {
    syscall(SYS_SCHED_THREAD_EXIT, exit_code);
    while (true);
}

void process_exit(int exit_code) {
    syscall(SYS_SCHED_PROCESS_EXIT, exit_code);
    while (true);
}