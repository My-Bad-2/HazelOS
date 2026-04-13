#include "api/ipc.h"

#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "api/capability.h"
#include "syscall.h"

int ipc_channel_create(uint64_t* cap1_out, uint64_t* cap2_out) {
    uint64_t caps[2] = {0, 0};
    int ret          = (int)syscall(SYS_IPC_ENDPOINT_CREATE, (long)caps, (long)(caps + 1));

    if (ret == 0) {
        if (cap1_out) *cap1_out = caps[0];
        if (cap2_out) *cap2_out = caps[1];
    }

    return ret;
}

int ipc_port_create(uint64_t* port_cap_out) {
    return (int)syscall(SYS_IPC_PORT_CREATE, (long)port_cap_out);
}

int ipc_close(uint64_t cap_id) {
    return cap_close(cap_id);
}

int ipc_bind(uint64_t port_cap, uint64_t chan_cap, uint64_t key) {
    return (int)syscall(SYS_IPC_PORT_BIND, (long)port_cap, (long)chan_cap, (long)key);
}

int ipc_wait_many(
    uint64_t port_cap,
    struct port_event* events,
    size_t max_events,
    size_t* out_count,
    int timeout_ms
) {
    return (int)syscall(
        SYS_IPC_PORT_WAIT,
        (long)port_cap,
        (long)events,
        (long)max_events,
        (long)out_count,
        timeout_ms
    );
}

int ipc_wait(uint64_t port_cap, struct port_event* out_event, int timeout_ms) {
    struct port_event zx_event;
    size_t returned = 0;

    int ret = ipc_wait_many(port_cap, &zx_event, 1, &returned, timeout_ms);

    if (ret == 0 && returned > 0 && out_event) {
        out_event->key     = zx_event.key;
        out_event->signals = zx_event.signals;
    }

    return ret;
}

int ipc_send_urgent(uint64_t chan_cap, const void* data, size_t len) {
    struct ipc_msg msg = {
        .data      = (void*)data,
        .data_len  = len,
        .caps      = nullptr,
        .cap_count = 0,
        .flags     = IPC_FLAG_URGENT
    };

    return (int)syscall(SYS_IPC_CHANNEL_WRITE, (long)chan_cap, (long)&msg);
}

int ipc_send(
    uint64_t chan_cap,
    const void* data,
    size_t len,
    const uint64_t* caps,
    size_t num_caps
) {
    struct cap_disp disp_caps[num_caps > 0 ? num_caps : 1];

    for (size_t i = 0; i < num_caps; i++) {
        disp_caps[i].cap_id = caps[i];
        disp_caps[i].rights = RIGHT_ALL;
        disp_caps[i].op     = IPC_CAP_OP_COPY;
    }

    struct ipc_msg msg =
        {.data = (void*)data, .data_len = len, .caps = disp_caps, .cap_count = num_caps};

    return (int)syscall(SYS_IPC_CHANNEL_WRITE, (long)chan_cap, (long)&msg);
}

int ipc_recv(
    uint64_t chan_cap,
    void* buffer,
    size_t max_len,
    size_t* actual_len,
    uint64_t* cap_buffer,
    size_t max_caps,
    size_t* actual_caps,
    uint32_t* badge_out,
    int timeout_ms
) {
    struct cap_disp disp_caps[max_caps > 0 ? max_caps : 1];

    struct ipc_msg msg =
        {.data = buffer, .data_len = max_len, .caps = disp_caps, .cap_count = max_caps};

    int ret = (int)syscall(
        SYS_IPC_CHANNEL_READ,
        (long)chan_cap,
        (long)&msg,
        (long)badge_out,
        (long)timeout_ms
    );

    if (actual_len) *actual_len = msg.data_len;

    if (actual_caps) {
        *actual_caps = msg.cap_count;

        if (ret == 0 && cap_buffer)
            for (size_t i = 0; i < msg.cap_count; i++) cap_buffer[i] = disp_caps[i].cap_id;
    }

    return ret;
}

int ipc_call(
    uint64_t chan_cap,
    const void* req_data,
    size_t req_len,
    const uint64_t* req_caps,
    size_t req_num_caps,
    void* resp_buffer,
    size_t resp_max_len,
    size_t* resp_actual_len,
    uint64_t* resp_cap_buffer,
    size_t resp_max_caps,
    size_t* resp_actual_caps,
    uint32_t* badge_out,
    int timeout_ms
) {
    struct cap_disp tx_disp[req_num_caps > 0 ? req_num_caps : 1];
    for (size_t i = 0; i < req_num_caps; i++) {
        tx_disp[i].cap_id = req_caps[i];
        tx_disp[i].rights = 0x7fff;
        tx_disp[i].op     = 0;
    }

    struct ipc_msg tx_msg =
        {.data = (void*)req_data, .data_len = req_len, .caps = tx_disp, .cap_count = req_num_caps};

    struct cap_disp rx_disp[resp_max_caps > 0 ? resp_max_caps : 1];
    struct ipc_msg rx_msg = {
        .data      = resp_buffer,
        .data_len  = resp_max_len,
        .caps      = rx_disp,
        .cap_count = resp_max_caps
    };

    int ret = (int)syscall(
        SYS_IPC_CHANNEL_CALL,
        (long)chan_cap,
        (long)&tx_msg,
        (long)&rx_msg,
        (long)timeout_ms
    );

    if (resp_actual_len) *resp_actual_len = rx_msg.data_len;

    if (resp_actual_caps) {
        *resp_actual_caps = rx_msg.cap_count;

        if (ret == 0 && resp_cap_buffer)
            for (size_t i = 0; i < rx_msg.cap_count; i++) resp_cap_buffer[i] = rx_disp[i].cap_id;
    }

    if (badge_out) *badge_out = 0;
    return ret;
}

int ipc_send_msg(
    uint64_t chan_cap,
    const void* data,
    size_t len,
    const uint64_t* caps,
    size_t cap_count
) {
    return ipc_send(chan_cap, data, len, caps, cap_count);
}

int ipc_recv_msg(
    uint64_t chan_cap,
    uint64_t port_cap,
    void* buffer,
    size_t max_len,
    uint64_t* caps_out,
    size_t max_caps,
    size_t* recv_len,
    size_t* recv_caps
) {
    if (port_cap > 0) {
        struct port_event event;
        int wait_ret = ipc_wait(port_cap, &event, -1);

        if (wait_ret < 0) return wait_ret;
    }

    uint32_t badge_out;
    return ipc_recv(
        chan_cap,
        buffer,
        max_len,
        recv_len,
        caps_out,
        max_caps,
        recv_caps,
        &badge_out,
        10
    );
}

int ipc_send_vector(
    uint64_t chan_cap,
    struct ipc_iovec* vectors,
    size_t vec_count,
    const uint64_t* caps,
    size_t cap_count
) {
    struct cap_disp disp_caps[cap_count > 0 ? cap_count : 1];
    for (size_t i = 0; i < cap_count; i++) {
        disp_caps[i].cap_id = caps[i];
        disp_caps[i].rights = RIGHT_ALL;
        disp_caps[i].op     = IPC_CAP_OP_COPY;
    }

    struct ipc_msg msg = {
        .data      = (void*)vectors,
        .data_len  = vec_count,
        .caps      = disp_caps,
        .cap_count = cap_count,
        .flags     = IPC_FLAG_IOVEC
    };

    return (int)syscall(SYS_IPC_CHANNEL_WRITE, (long)chan_cap, (long)&msg);
}

int ipc_peek(uint64_t chan_cap, size_t* required_data_len, size_t* required_cap_count) {
    struct ipc_msg msg =
        {.data = nullptr, .data_len = 0, .caps = nullptr, .cap_count = 0, .flags = IPC_FLAG_PEEK};

    int ret = (int)syscall(SYS_IPC_CHANNEL_READ, (long)chan_cap, (long)&msg, 0, 0);
    if (ret == 0) {
        if (required_data_len) *required_data_len = msg.data_len;
        if (required_cap_count) *required_cap_count = msg.cap_count;
    }

    return ret;
}

int channel_forward(uint64_t src_ep_cap, uint64_t dest_ep_cap) {
    return syscall(SYS_IPC_CHANNEL_FORWARD, (long)src_ep_cap, (long)dest_ep_cap);
}