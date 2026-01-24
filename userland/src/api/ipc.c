#include "api/ipc.h"

#include <stdatomic.h>
#include <stdint.h>
#include <string.h>

int ipc_ring_write(ipc_ring_t* ring, const void* src, uint32_t len) {
    if (len > IPC_RING_SIZE) {
        return 1;
    }

    uint32_t tail = atomic_load_explicit(&ring->tail, memory_order_relaxed);
    uint32_t head = atomic_load_explicit(&ring->head, memory_order_acquire);

    uint32_t used = tail - head;

    if ((IPC_RING_SIZE - used) < len) {
        return 1;
    }

    uint32_t idx         = tail & IPC_RING_MASK;
    uint32_t first_chunk = IPC_RING_SIZE - 1;

    if (len <= first_chunk) {
        memcpy(&ring->data[idx], src, len);
    } else {
        memcpy(&ring->data[idx], src, first_chunk);
        memcpy(&ring->data[0], (uint8_t*)src + first_chunk, len - first_chunk);
    }

    // Commit write
    atomic_store_explicit(&ring->tail, tail + len, memory_order_release);

    return (used == 0) ? 2 : 0;
}

uint32_t ipc_ring_read(ipc_ring_t* ring, void* dest, uint32_t max_len) {
    uint32_t tail = atomic_load_explicit(&ring->tail, memory_order_acquire);
    uint32_t head = atomic_load_explicit(&ring->head, memory_order_relaxed);

    uint32_t available = tail - head;

    if (available == 0) {
        return 0;
    }

    uint32_t to_read     = (available < max_len) ? available : max_len;
    uint32_t idx         = head & IPC_RING_MASK;
    uint32_t first_chunk = IPC_RING_SIZE - idx;

    if (to_read <= first_chunk) {
        memcpy(dest, &ring->data[idx], to_read);
    } else {
        memcpy(dest, &ring->data[idx], first_chunk);
        memcpy((uint8_t*)dest + first_chunk, &ring->data[0], to_read - first_chunk);
    }

    atomic_store_explicit(&ring->head, head + to_read, memory_order_release);
    return to_read;
}