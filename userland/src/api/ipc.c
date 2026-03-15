#include "api/ipc.h"

#include <errno.h>
#include <stdatomic.h>
#include <stdint.h>

#include "api/syscalls.h"

int ipc_send_msg(
    int32_t chan_handle,
    const void* data,
    uint32_t len,
    int32_t* handles,
    uint32_t handle_count
) {
    if (handle_count > IPC_MAX_HANDLES) {
        return -EINVAL;
    }

    return sys_ipc_send_msg(chan_handle, (void*)data, len, handles, handle_count);
}

int ipc_recv_msg(
    int32_t chan_handle,
    int32_t port_set,
    void* buffer,
    uint32_t max_len,
    int32_t* handles_out,
    uint32_t max_handles,
    uint32_t* recv_len,
    uint32_t* recv_handles
) {
    ipc_msg_info_t info = {
        .data_buffer      = buffer,
        .data_size_max    = max_len,
        .data_size_actual = 0,
        .handles_buffer   = handles_out,
        .handles_max      = max_handles,
        .handles_actual   = 0
    };

    while (1) {
        int ret = sys_ipc_recv_msg(chan_handle, &info);

        if (ret == -EAGAIN && port_set >= 0) {
            ipc_event_t event;

            int wait_ret = ipc_wait(port_set, &event, -1);
            if (wait_ret < 0) {
                return wait_ret;
            }

            continue;
        }

        if (ret == 0 || ret == -E2BIG) {
            if (recv_len) {
                *recv_len = info.data_size_actual;
            }
            if (recv_handles) {
                *recv_handles = info.handles_actual;
            }
        }

        return ret;
    }
}