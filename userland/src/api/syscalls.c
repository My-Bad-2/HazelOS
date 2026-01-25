#include "api/syscalls.h"

#include <stddef.h>
#include <stdint.h>

#include "syscall.h"

#define TIMER_FLAG_PERIODIC (1 << 0)

int64_t write(int fd, const char* str, size_t len) {
    return syscall(SYS_WRITE, (long)fd, (long)str, (long)len);
}

int ipc_create_channel(int32_t* handles, uintptr_t* ring_vaddr_out) {
    long ret = syscall(SYS_IPC_CREATE_CHANNEL, (long)handles, (long)ring_vaddr_out);

    if (ret < 0) {
        return -1;
    }

    return 0;
}

int ipc_create_port_set(void) {
    int32_t handle;

    long ret = syscall(SYS_IPC_CREATE_PORT_SET, (long)&handle);

    if (ret > 0) {
        return -1;
    }

    return handle;
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

int ipc_send_handles(int32_t handle, int32_t* handles, size_t n) {
    return syscall(SYS_IPC_SEND_HANDLES, handle, (long)handles, (long)n);
}

int ipc_recv_handles(int32_t handle, int32_t* handles, size_t max_count) {
    return syscall(SYS_IPC_RECV_HANDLES, handle, (long)handles, (long)max_count);
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