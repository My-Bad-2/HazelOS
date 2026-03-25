#include "api/ipc.h"

#include <stdatomic.h>
#include <stdint.h>

#include "api/syscalls.h"
#include "syscall.h"

int ipc_channel_create(uint32_t* cap1_out, uint32_t* cap2_out) {
    uint32_t caps[2] = {0, 0};
    int ret          = (int)syscall(SYS_IPC_CHANNEL_CREATE, (long)caps);

    if (ret == 0) {
        if (cap1_out) {
            *cap1_out = caps[0];
        }

        if (cap2_out) {
            *cap2_out = caps[1];
        }
    }

    return ret;
}

int ipc_port_create(uint32_t* port_cap_out) {
    return (int)syscall(SYS_IPC_PORT_CREATE, (long)port_cap_out);
}

int ipc_close(uint32_t cap_id) {
    return (int)syscall(SYS_IPC_CLOSE, (long)cap_id);
}

int ipc_bind(uint32_t port_cap, uint32_t chan_cap, uint64_t key) {
    return (int)syscall(SYS_IPC_BIND, (long)port_cap, (long)chan_cap, (long)key);
}

int ipc_wait(uint32_t port_cap, struct ipc_event* out_event, int timeout_ms) {
    return (int)syscall(SYS_IPC_WAIT, (long)port_cap, (long)out_event, (long)timeout_ms);
}

int ipc_send(
    uint32_t chan_cap,
    const void* data,
    size_t len,
    const uint32_t* caps,
    size_t num_caps
) {
    struct ipc_msg_info info = {
        .data_buffer      = (void*)data,
        .data_size_max    = len,
        .data_size_actual = 0,
        .caps_buffer      = (uint32_t*)caps,
        .caps_max         = num_caps,
        .caps_actual      = 0
    };

    return (int)syscall(SYS_IPC_SEND, (long)chan_cap, (long)&info);
}

int ipc_recv(
    uint32_t chan_cap,
    void* buffer,
    size_t max_len,
    size_t* actual_len,
    uint32_t* cap_buffer,
    size_t max_caps,
    size_t* actual_caps
) {
    struct ipc_msg_info info = {
        .data_buffer      = buffer,
        .data_size_max    = max_len,
        .data_size_actual = 0,
        .caps_buffer      = cap_buffer,
        .caps_max         = max_caps,
        .caps_actual      = 0
    };

    int ret = (int)syscall(SYS_IPC_RECV, (long)chan_cap, (long)&info);

    if (actual_len) {
        *actual_len = info.data_size_actual;
    }

    if (actual_caps) *actual_caps = info.caps_actual;

    return ret;
}

int ipc_call(
    uint32_t chan_cap,
    const void* req_data,
    size_t req_len,
    const uint32_t* req_caps,
    size_t req_num_caps,
    void* resp_buffer,
    size_t resp_max_len,
    size_t* resp_actual_len,
    uint32_t* resp_cap_buffer,
    size_t resp_max_caps,
    size_t* resp_actual_caps
) {
    struct ipc_msg_info tx_info = {
        .data_buffer      = (void*)req_data,
        .data_size_max    = req_len,
        .data_size_actual = 0,
        .caps_buffer      = (uint32_t*)req_caps,
        .caps_max         = req_num_caps,
        .caps_actual      = 0
    };

    struct ipc_msg_info rx_info = {
        .data_buffer      = resp_buffer,
        .data_size_max    = resp_max_len,
        .data_size_actual = 0,
        .caps_buffer      = resp_cap_buffer,
        .caps_max         = resp_max_caps,
        .caps_actual      = 0
    };

    int ret = (int)syscall(SYS_IPC_CALL, (long)chan_cap, (long)&tx_info, (long)&rx_info);

    if (resp_actual_len) {
        *resp_actual_len = rx_info.data_size_actual;
    }

    if (resp_actual_caps) {
        *resp_actual_caps = rx_info.caps_actual;
    }

    return ret;
}

int ipc_send_msg(
    uint32_t chan_cap,
    const void* data,
    size_t len,
    const uint32_t* caps,
    size_t cap_count
) {
    return ipc_send(chan_cap, data, len, caps, cap_count);
}

int ipc_recv_msg(
    uint32_t chan_cap,
    uint32_t port_cap,
    void* buffer,
    size_t max_len,
    uint32_t* caps_out,
    size_t max_caps,
    size_t* recv_len,
    size_t* recv_caps
) {
    if (port_cap > 0) {
        struct ipc_event event;
        int wait_ret = ipc_wait(port_cap, &event, -1);

        if (wait_ret < 0) {
            return wait_ret;
        }
    }

    int ret = ipc_recv(chan_cap, buffer, max_len, recv_len, caps_out, max_caps, recv_caps);
    return ret;
}