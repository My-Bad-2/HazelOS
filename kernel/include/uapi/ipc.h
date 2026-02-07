#ifndef KERNEL_UAPI_IPC_H
#define KERNEL_UAPI_IPC_H 1

#include <stdatomic.h>
#include <stdint.h>

#define IPC_RING_SIZE (4096 * 4)

#define IPC_EVENT_READABLE (1 << 0)
#define IPC_EVENT_WRITABLE (1 << 1)
#define IPC_EVENT_CLOSED   (1 << 2)

typedef struct [[gnu::aligned(64)]] {
    atomic_uint tail;
    atomic_uint head;

    uint8_t data[IPC_RING_SIZE];
} ipc_ring_t;

typedef struct {
    uint64_t key;     // Cookie
    uint32_t events;  // Bitmask of what happened
    int32_t handle;   // Handle that triggered the event
} ipc_event_t;

#endif