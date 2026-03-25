#ifndef KERNEL_UAPI_IPC_H
#define KERNEL_UAPI_IPC_H 1

#include <stdatomic.h>
#include <stdint.h>

#define IPC_MAX_HANDLES 1024

#define IPC_EVENT_READABLE (1 << 0)
#define IPC_EVENT_WRITABLE (1 << 1)
#define IPC_EVENT_CLOSED   (1 << 2)

struct ipc_msg_info {
    void* data_buffer;
    size_t data_size_max;
    size_t data_size_actual;

    uint32_t* caps_buffer;
    size_t caps_max;
    size_t caps_actual;
};

struct ipc_event {
    uint64_t key;
    uint32_t events;
};

int ipc_channel_create(uint32_t* cap1_out, uint32_t* cap2_out);
int ipc_port_create(uint32_t* port_cap_out);
int ipc_close(uint32_t cap_id);

int ipc_bind(uint32_t port_cap, uint32_t chan_cap, uint64_t key);
int ipc_wait(uint32_t port_cap, struct ipc_event* out_event, int timeout_ms);

int ipc_send(
    uint32_t chan_cap,
    const void* data,
    size_t len,
    const uint32_t* caps,
    size_t num_caps
);

int ipc_recv(
    uint32_t chan_cap,
    void* buffer,
    size_t max_len,
    size_t* actual_len,
    uint32_t* cap_buffer,
    size_t max_caps,
    size_t* actual_caps
);

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
);

int ipc_send_msg(
    uint32_t chan_cap,
    const void* data,
    size_t len,
    const uint32_t* caps,
    size_t cap_count
);

int ipc_recv_msg(
    uint32_t chan_cap,
    uint32_t port_cap,
    void* buffer,
    size_t max_len,
    uint32_t* caps_out,
    size_t max_caps,
    size_t* recv_len,
    size_t* recv_caps
);

#endif