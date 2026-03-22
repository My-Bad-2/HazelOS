#include "api/syscalls.h"

#include <errno.h>
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

int ipc_create_channel(int32_t* handles) {
    long ret = syscall(SYS_IPC_CREATE_CHANNEL, (long)handles);

    if (ret != 0) {
        return -1;
    }

    return 0;
}

int ipc_create_port_set(int32_t* handle) {
    long ret = syscall(SYS_IPC_CREATE_PORT_SET, (long)handle);

    if (ret != 0) {
        return -1;
    }

    return 0;
}

int ipc_bind(int32_t port_set, int32_t channel, uint64_t key) {
    return syscall(SYS_IPC_BIND, port_set, channel, (long)key);
}

int ipc_notify(int32_t channel) {
    return syscall(SYS_IPC_NOTIFY, channel);
}

int ipc_wait(int32_t port_set, ipc_event_t* event, int timeout_ms) {
    return syscall(SYS_IPC_WAIT, port_set, (long)event, timeout_ms);
}

int ipc_handle_close(int32_t handle) {
    return syscall(SYS_HANDLE_CLOSE, handle);
}

int sys_ipc_send_msg(
    int32_t chan_handle,
    const void* user_data,
    size_t size,
    int32_t* user_handles,
    size_t num_handles
) {
    if (num_handles > IPC_MAX_HANDLES) {
        return -EINVAL;
    }

    return syscall(
        SYS_IPC_SEND_MSG,
        chan_handle,
        (long)user_data,
        (long)size,
        (long)user_handles,
        (long)num_handles
    );
}

int sys_ipc_recv_msg(int32_t chan_handle, ipc_msg_info_t* info) {
    return syscall(SYS_IPC_RECV_MSG, (long)chan_handle, (long)info);
}

int ipc_shm_alloc(size_t size, int flags, int32_t* handle_out, uintptr_t* vaddr_out) {
    return syscall(SYS_IPC_SHM_ALLOC, (long)size, flags, (long)handle_out, (long)vaddr_out);
}

int ipc_timer_arm_oneshot(
    int32_t port_handle,
    uint64_t user_key,
    uint64_t deadline_ms,
    int32_t* handle_out
) {
    return syscall(
        SYS_IPC_TIMER_ARM,
        port_handle,
        (long)user_key,
        (long)deadline_ms,
        0,
        (long)handle_out
    );
}

int ipc_timer_arm_periodic(
    int32_t port_handle,
    uint64_t user_key,
    uint64_t deadline_ms,
    int32_t* handle_out
) {
    return syscall(
        SYS_IPC_TIMER_ARM,
        port_handle,
        (long)user_key,
        (long)deadline_ms,
        TIMER_FLAG_PERIODIC,
        (long)handle_out
    );
}

int fork(void) {
    return syscall(SYS_FORK, 0);
}