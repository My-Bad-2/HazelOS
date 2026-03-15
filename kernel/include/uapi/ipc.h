#ifndef KERNEL_UAPI_IPC_H
#define KERNEL_UAPI_IPC_H 1

#include <stdatomic.h>
#include <stdint.h>

#define IPC_EVENT_READABLE (1 << 0)
#define IPC_EVENT_WRITABLE (1 << 1)
#define IPC_EVENT_CLOSED   (1 << 2)

typedef struct {
    void* data_buffer;
    size_t data_size_max;
    size_t data_size_actual;

    int32_t* handles_buffer;
    size_t handles_max;
    size_t handles_actual;
} ipc_msg_info_t;

typedef struct {
    uint64_t key;     // Cookie
    uint32_t events;  // Bitmask of what happened
    int32_t handle;   // Handle that triggered the event
} ipc_event_t;

#endif