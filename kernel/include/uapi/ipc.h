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

#define IPC_RIGHT_NONE      0
#define IPC_RIGHT_READ      (1 << 0)  // Can read / wait
#define IPC_RIGHT_WRITE     (1 << 1)  // Can write / notify
#define IPC_RIGHT_TRANSFER  (1 << 2)  // Can send this handle to others
#define IPC_RIGHT_MAP       (1 << 3)  // Can Map (for Shared Mem)
#define IPC_RIGHT_DUPLICATE (1 << 4)  // Can Clone the Handle
#define IPC_RIGHT_INSPECT   (1 << 5)  // Can Inspect

#define IPC_RIGHTS_ALL UINT32_MAX
#define IPC_RIGHTS_READ_ONLY \
    (IPC_RIGHT_READ | IPC_RIGHT_TRANSFER | IPC_RIGHT_MAP | IPC_RIGHT_DUPLICATE | IPC_RIGHT_INSPECT)
#define IPC_RIGHTS_WRITE_ONLY (IPC_RIGHT_WRITE | IPC_RIGHT_TRANSFER | IPC_RIGHT_INSPECT)

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

#endif