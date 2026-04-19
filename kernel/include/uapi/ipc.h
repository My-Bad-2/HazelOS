#ifndef KERNEL_UAPI_IPC_H
#define KERNEL_UAPI_IPC_H 1

#include <stdatomic.h>
#include <stdint.h>

#define IPC_SIGNAL_READABLE    (1ul << 0)
#define IPC_SIGNAL_WRITABLE    (1ul << 1)
#define IPC_SIGNAL_PEER_CLOSED (1ul << 2)

#define IPC_CAP_OP_COPY 0
#define IPC_CAP_OP_MOVE 1

#define IPC_FLAG_PEEK   (1 << 0)
#define IPC_FLAG_IOVEC  (1 << 1)
#define IPC_FLAG_URGENT (1 << 2)

#define IPC_EVENT_LEVEL_TRIGGERED false
#define IPC_EVENT_EDGE_TRIGGERED  true

#define IPC_PORT_TYPE_SIGNAL 0
#define IPC_PORT_TYPE_PAGER  1

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

struct pager_packet {
    uint64_t offset;
    uint64_t length;
};

struct port_event {
    uint64_t key;
    uint32_t type;

    union {
        struct {
            uint32_t signals;
            uint32_t count;
        } signal;

        struct pager_packet pager;
    } data;
};

#endif