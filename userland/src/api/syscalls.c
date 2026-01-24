#include "api/syscalls.h"

#include <stddef.h>
#include <stdint.h>

#include "syscall.h"

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
    if (ret < 0) return -1;
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

int handle_close(int32_t handle) {
    return syscall(SYS_HANDLE_CLOSE, handle);
}