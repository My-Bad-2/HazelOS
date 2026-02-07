#include "api/ipc.h"

#include <errno.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "api/syscalls.h"

#define MSG_MAGIC 0xAABBCCDD

int ipc_ring_write(ipc_ring_t* ring, const void* src, uint32_t len) {
    if (len > IPC_RING_SIZE) {
        return 1;
    }

    uint32_t head = atomic_load_explicit(&ring->head, memory_order_acquire);
    uint32_t tail = atomic_load_explicit(&ring->tail, memory_order_relaxed);

    uint32_t used = tail - head;
    uint32_t free = IPC_RING_SIZE - used;

    if (free < len) {
        return 1;
    }

    uint32_t idx    = tail & IPC_RING_MASK;
    uint32_t to_end = IPC_RING_SIZE - idx;

    if (len <= to_end) {
        memcpy(&ring->data[idx], src, len);
    } else {
        memcpy(&ring->data[idx], src, to_end);
        memcpy(&ring->data[0], (uint8_t*)src + to_end, len - to_end);
    }

    atomic_store_explicit(&ring->tail, tail + len, memory_order_release);
    return (used == 0) ? 2 : 0;
}

uint32_t ipc_ring_read(ipc_ring_t* ring, void* dest, uint32_t max_len) {
    uint32_t head = atomic_load_explicit(&ring->head, memory_order_relaxed);
    uint32_t tail = atomic_load_explicit(&ring->tail, memory_order_acquire);

    uint32_t available = tail - head;
    if (available == 0) {
        return 0;
    }

    uint32_t to_read = (available < max_len) ? available : max_len;

    uint32_t idx    = head & IPC_RING_MASK;
    uint32_t to_end = IPC_RING_SIZE - idx;

    if (to_read <= to_end) {
        memcpy(dest, &ring->data[idx], to_read);
    } else {
        memcpy(dest, &ring->data[idx], to_end);
        memcpy((uint8_t*)dest + to_end, &ring->data[0], to_read - to_end);
    }

    atomic_store_explicit(&ring->head, head + to_read, memory_order_release);
    return to_read;
}

int ipc_send_msg(
    int32_t chan_handle,
    ipc_ring_t* ring,
    const void* data,
    uint32_t len,
    int32_t* handles,
    uint32_t handle_count
) {
    if (len > IPC_RING_SIZE / 2) {
        return -EBADF;
    }

    if (handle_count > IPC_MAX_HANDLES) {
        return -EINVAL;
    }

    ipc_message_header_t header = {
        .magic        = MSG_MAGIC,
        .payload_len  = len,
        .handle_count = handle_count,
        .flags        = 0,
    };

    uint32_t total_size = sizeof(header) + len;

    for (int i = 0; i < 1000; ++i) {
        uint32_t head = atomic_load_explicit(&ring->head, memory_order_acquire);
        uint32_t tail = atomic_load_explicit(&ring->tail, memory_order_relaxed);

        uint32_t used = tail - head;

        if ((IPC_RING_SIZE - used) >= total_size) {
            break;
        }

        // Spin delay

        if (i == 999) {
            // Ring full, try later
            return -EAGAIN;
        }
    }

    // We must send handles to the kernel before data is visible to the peer in order to ensure that
    // when the peer sees data, handles are already queued.
    if (handle_count > 0) {
        int ret = ipc_send_handles(chan_handle, handles, handle_count);

        if (ret < 0) {
            return ret;
        }
    }

    uint32_t tail = atomic_load_explicit(&ring->tail, memory_order_relaxed);
    uint32_t idx  = tail & IPC_RING_MASK;

    for (size_t i = 0; i < sizeof(header); ++i) {
        ring->data[(idx + i) & IPC_RING_MASK] = ((uint8_t*)&header)[i];
    }

    for (size_t i = 0; i < len; ++i) {
        ring->data[(idx + sizeof(header) + i) & IPC_RING_MASK] = ((const uint8_t*)data)[i];
    }

    atomic_store_explicit(&ring->tail, tail + total_size, memory_order_release);

    ipc_notify(chan_handle);
    return 0;
}

int ipc_recv_msg(
    int32_t chan_handle,
    int32_t port_set,
    ipc_ring_t* ring,
    void* buffer,
    uint32_t max_len,
    int32_t* handles_out,
    uint32_t max_handles,
    uint32_t* recv_len,
    uint32_t* recv_handles
) {
    (void)max_handles;
    ipc_message_header_t header;
    ipc_event_t event;

    int count = 0;

    while (true) {
        uint32_t head  = atomic_load_explicit(&ring->head, memory_order_relaxed);
        uint32_t tail  = atomic_load_explicit(&ring->tail, memory_order_acquire);
        uint32_t avail = tail - head;

        if (avail >= sizeof(header)) {
            break;
        }

        ipc_wait(port_set, &event, 100);
    }

    uint32_t head = atomic_load_explicit(&ring->head, memory_order_relaxed);
    uint32_t idx  = head & IPC_RING_MASK;

    for (size_t i = 0; i < sizeof(header); ++i) {
        ((uint8_t*)&header)[i] = ring->data[(idx + i) & IPC_RING_MASK];
    }

    if (header.magic != MSG_MAGIC) {
        return -EIO;
    }

    if (header.payload_len > max_len) {
        return -ENOENT;
    }

    uint32_t total_size = sizeof(header) + header.payload_len;

    while (true) {
        uint32_t tail = atomic_load_explicit(&ring->tail, memory_order_acquire);

        if ((tail - head) >= total_size) {
            break;
        }

        ipc_wait(port_set, &event, -1);
    }

    for (size_t i = 0; i < header.payload_len; ++i) {
        ((uint8_t*)buffer)[i] = ring->data[(idx + sizeof(header) + i) & IPC_RING_MASK];
    }

    size_t recv = 0;

    char buf[128];
    while (recv < header.handle_count) {
        recv +=
            (size_t)ipc_recv_handles(chan_handle, &handles_out[recv], header.handle_count - recv);

        if (recv < header.handle_count) {
            ipc_wait(port_set, &event, 100);
        }
    }

    atomic_store_explicit(&ring->head, head + total_size, memory_order_release);

    if (recv_len) {
        *recv_len = header.payload_len;
    }

    if (recv_handles) {
        *recv_handles = recv;
    }

    return 0;
}