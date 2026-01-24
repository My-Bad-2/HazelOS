#ifndef KERNEL_UAPI_IPC_H
#define KERNEL_UAPI_IPC_H 1

#include <stdatomic.h>
#include <stdint.h>

#define IPC_RING_SIZE   4096
#define IPC_RING_MASK   (IPC_RING_SIZE - 1)
#define IPC_MAX_HANDLES 1024

#define IPC_EVENT_READABLE (1 << 0)
#define IPC_EVENT_WRITABLE (1 << 1)
#define IPC_EVENT_CLOSED   (1 << 2)

// Shared Memory Ring Buffer
typedef struct [[gnu::aligned(64)]] {
    atomic_uint_fast32_t tail;
    atomic_uint_fast32_t head;

    uint8_t data[IPC_RING_SIZE];
} ipc_ring_t;

typedef struct {
    uint64_t key;     // Cookie
    uint32_t events;  // Bitmask of what happened
    int32_t handle;   // Handle that triggered the event
} ipc_event_t;

int ipc_ring_write(ipc_ring_t* ring, const void* src, uint32_t len);
uint32_t ipc_ring_read(ipc_ring_t* ring, void* dest, uint32_t max_len);

#endif