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
    long ret = syscall(SYS_IPC_CHANNEL_CREATE, (long)handles);

    if (ret != 0) {
        return -1;
    }

    return 0;
}

int ipc_create_port_set(int32_t* handle) {
    long ret = syscall(SYS_IPC_PORT_CREATE, (long)handle);

    if (ret != 0) {
        return -1;
    }

    return 0;
}

int ipc_bind(int32_t port_set, int32_t channel, uint64_t key) {
    return syscall(SYS_IPC_BIND, port_set, channel, (long)key);
}

int ipc_notify(int32_t channel) {
    return syscall(SYS_IPC_CALL, channel);
}

int ipc_wait(int32_t port_set, ipc_event_t* event, int timeout_ms) {
    return syscall(SYS_IPC_WAIT, port_set, (long)event, timeout_ms);
}

int ipc_close(int32_t handle) {
    return syscall(SYS_IPC_CLOSE, handle);
}

int ipc_send(
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
        SYS_IPC_SEND,
        chan_handle,
        (long)user_data,
        (long)size,
        (long)user_handles,
        (long)num_handles
    );
}

int ipc_recv(int32_t chan_handle, ipc_msg_info_t* info) {
    return syscall(SYS_IPC_RECV, (long)chan_handle, (long)info);
}

int fork(void) {
    return syscall(SYS_FORK, 0);
}