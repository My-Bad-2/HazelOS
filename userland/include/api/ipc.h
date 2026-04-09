#ifndef KERNEL_UAPI_IPC_H
#define KERNEL_UAPI_IPC_H 1

#include <stdatomic.h>
#include <stdint.h>

#define SYS_CATEGORY_IPC 0x0200

#define SYS_IPC_ENDPOINT_CREATE (SYS_CATEGORY_IPC | 0x01)
#define SYS_IPC_PORT_CREATE     (SYS_CATEGORY_IPC | 0x02)
#define SYS_IPC_PORT_BIND       (SYS_CATEGORY_IPC | 0x03)
#define SYS_IPC_PORT_WAIT       (SYS_CATEGORY_IPC | 0x04)
#define SYS_IPC_CHANNEL_WRITE   (SYS_CATEGORY_IPC | 0x05)
#define SYS_IPC_CHANNEL_READ    (SYS_CATEGORY_IPC | 0x06)
#define SYS_IPC_CHANNEL_CALL    (SYS_CATEGORY_IPC | 0x07)

#define IPC_SIGNAL_READABLE    (1ul << 0)
#define IPC_SIGNAL_WRITABLE    (1ul << 1)
#define IPC_SIGNAL_PEER_CLOSED (1ul << 2)

#define IPC_CAP_OP_COPY 0
#define IPC_CAP_OP_MOVE 1

#define IPC_FLAG_PEEK  (1 << 0)
#define IPC_FLAG_IOVEC (1 << 1)

struct cap_disp {
    uint64_t cap_id;
    uint16_t rights;
    uint8_t op;
};

struct ipc_iovec {
    void* base;
    size_t len;
};

struct ipc_msg {
    void* data;
    size_t data_len;

    struct cap_disp* caps;
    size_t cap_count;

    uint32_t flags;
};

struct port_event {
    uint64_t key;
    uint32_t signals;
    uint32_t reserved;
};

int ipc_channel_create(uint64_t* cap1_out, uint64_t* cap2_out);
int ipc_port_create(uint64_t* port_cap_out);
int ipc_close(uint64_t cap_id);

int ipc_bind(uint64_t port_cap, uint64_t chan_cap, uint64_t key);
int ipc_wait(uint64_t port_cap, struct port_event* out_event, int timeout_ms);

int ipc_send(
    uint64_t chan_cap,
    const void* data,
    size_t len,
    const uint64_t* caps,
    size_t num_caps
);

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
);

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
);

int ipc_send_msg(
    uint64_t chan_cap,
    const void* data,
    size_t len,
    const uint64_t* caps,
    size_t cap_count
);

int ipc_recv_msg(
    uint64_t chan_cap,
    uint64_t port_cap,
    void* buffer,
    size_t max_len,
    uint64_t* caps_out,
    size_t max_caps,
    size_t* recv_len,
    size_t* recv_caps
);

int ipc_send_vector(
    uint64_t chan_cap,
    struct ipc_iovec* vectors,
    size_t vec_count,
    const uint64_t* caps,
    size_t cap_count
);

int ipc_peek(uint64_t chan_cap, size_t* required_data_len, size_t* required_cap_count);

#endif