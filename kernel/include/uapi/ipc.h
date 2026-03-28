#ifndef KERNEL_UAPI_IPC_H
#define KERNEL_UAPI_IPC_H 1

#include <stdatomic.h>
#include <stdint.h>

#define IPC_EVENT_READABLE     (1 << 0)
#define IPC_EVENT_WRITABLE     (1 << 1)
#define IPC_EVENT_CLOSED       (1 << 2)
#define IPC_EVENT_NOTIFICATION (1 << 3)

struct ipc_msg_info {
    void* data_buffer;
    size_t data_size_max;
    size_t data_size_actual;

    uint64_t* caps_buffer;
    size_t caps_max;
    size_t caps_actual;

    uint64_t reply_cap_id;
    uint32_t sender_badge;
};

struct ipc_event {
    uint64_t key;
    uint64_t notification_bits;
    uint32_t events;
};

#endif