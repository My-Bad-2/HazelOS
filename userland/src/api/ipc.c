#include "api/ipc.h"

#include <errno.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "api/syscalls.h"

#define MSG_MAGIC 0xAABBCCDD

static inline uint32_t
ring_write_partial(ipc_ring_t* ring, uint32_t start_idx, const void* src, uint32_t len) {
    uint32_t capacity = ring->capacity;
    uint32_t to_end   = capacity - start_idx;

    if (len <= to_end) {
        memcpy(&ring->data[start_idx], src, len);
        return start_idx + len;
    } else {
        memcpy(&ring->data[start_idx], src, to_end);
        memcpy(&ring->data[0], (const uint8_t*)src + to_end, len - to_end);

        return len - to_end;
    }
}

static inline void
ring_read_partial(ipc_ring_t* ring, uint32_t start_idx, void* dest, uint32_t len) {
    uint32_t capacity = ring->capacity;
    uint32_t to_end   = capacity - start_idx;

    if (len <= to_end) {
        memcpy(dest, &ring->data[start_idx], len);
    } else {
        memcpy(dest, &ring->data[start_idx], to_end);
        memcpy((uint8_t*)dest + to_end, &ring->data[0], len - to_end);
    }
}

int ipc_ring_write(ipc_ring_t* ring, const void* src, uint32_t len) {
    uint32_t capacity = ring->capacity;

    if (len >= capacity) {
        return 1;
    }

    uint32_t head = atomic_load_explicit(&ring->head, memory_order_acquire);
    uint32_t tail = atomic_load_explicit(&ring->tail, memory_order_relaxed);

    uint32_t used = 0;

    if (tail >= head) {
        used = tail - head;
    } else {
        used = capacity - (head - tail);
    }

    uint32_t free = capacity - used - 1;

    if (free < len) {
        return 1;
    }

    uint32_t new_tail = ring_write_partial(ring, tail, src, len);

    atomic_store_explicit(&ring->tail, new_tail, memory_order_release);
    return (used == 0) ? 2 : 0;
}

uint32_t ipc_ring_read(ipc_ring_t* ring, void* dest, uint32_t max_len) {
    uint32_t capacity = ring->capacity;

    uint32_t head = atomic_load_explicit(&ring->head, memory_order_relaxed);
    uint32_t tail = atomic_load_explicit(&ring->tail, memory_order_acquire);

    if (head == tail) {
        return 0;
    }

    uint32_t available = 0;
    if (tail > head) {
        available = tail - head;
    } else {
        available = capacity - (head - tail);
    }

    uint32_t to_read = (available < max_len) ? available : max_len;

    ring_read_partial(ring, head, dest, to_read);

    uint32_t new_head = head + to_read;

    if (new_head >= capacity) {
        new_head -= capacity;
    }

    atomic_store_explicit(&ring->head, new_head, memory_order_release);
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

    uint32_t capacity = ring->capacity;

    ipc_message_header_t header = {
        .magic        = MSG_MAGIC,
        .payload_len  = len,
        .handle_count = handle_count,
        .flags        = 0,
    };

    uint32_t total_size = sizeof(header) + len;
    uint32_t tail       = 0;

    for (int i = 0; i < 1000; ++i) {
        uint32_t head = atomic_load_explicit(&ring->head, memory_order_acquire);
        tail          = atomic_load_explicit(&ring->tail, memory_order_relaxed);

        uint32_t used = capacity - (head - tail);

        if (tail >= head) {
            used = tail - head;
        }

        const uint32_t available = (capacity - used - 1);
        if (available >= total_size) {
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

    uint32_t curr_idx = tail;
    curr_idx          = ring_write_partial(ring, curr_idx, &header, sizeof(header));

    if (curr_idx >= capacity) {
        curr_idx -= capacity;
    }

    if (len > 0) {
        ring_write_partial(ring, curr_idx, data, len);
    }

    uint32_t new_tail = tail + total_size;

    if (new_tail >= capacity) {
        new_tail -= capacity;
    }

    atomic_store_explicit(&ring->tail, new_tail, memory_order_release);
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

    uint32_t capacity = ring->capacity;

    int count = 0;

    uint32_t head = 0;

    while (true) {
        head               = atomic_load_explicit(&ring->head, memory_order_relaxed);
        uint32_t tail      = atomic_load_explicit(&ring->tail, memory_order_acquire);
        uint32_t available = capacity - (head - tail);

        if (tail >= head) {
            available = tail - head;
        }

        if (available >= sizeof(header)) {
            break;
        }

        ipc_wait(port_set, &event, 100);
    }

    ring_read_partial(ring, head, &header, sizeof(header));

    if (header.magic != MSG_MAGIC) {
        return -EIO;
    }

    if (header.payload_len > max_len) {
        return -ENOENT;
    }

    uint32_t total_size = sizeof(header) + header.payload_len;

    while (true) {
        uint32_t tail = atomic_load_explicit(&ring->tail, memory_order_acquire);

        uint32_t available = capacity - (head - tail);

        if (tail >= head) {
            available = tail - head;
        }

        if (available >= total_size) {
            break;
        }

        ipc_wait(port_set, &event, -1);
    }

    uint32_t payload_idx = head + sizeof(header);

    if (payload_idx >= capacity) {
        payload_idx -= capacity;
    }

    if (header.payload_len > 0) {
        ring_read_partial(ring, payload_idx, buffer, header.payload_len);
    }

    size_t recv = 0;
    while (recv < header.handle_count) {
        int n = ipc_recv_handles(chan_handle, &handles_out[recv], header.handle_count - recv);

        if (n < 0) {
            return n;
        }

        recv += (size_t)n;
        if (recv < header.handle_count) {
            ipc_wait(port_set, &event, 100);
        }
    }

    uint32_t new_head = head + total_size;

    if (new_head >= capacity) {
        new_head -= capacity;
    }

    atomic_store_explicit(&ring->head, new_head, memory_order_release);

    if (recv_len) {
        *recv_len = header.payload_len;
    }

    if (recv_handles) {
        *recv_handles = recv;
    }

    return 0;
}

void* ipc_ring_peek(ipc_ring_t* ring, uint32_t* out_len) {
    uint32_t head = atomic_load_explicit(&ring->head, memory_order_relaxed);
    uint32_t cap  = ring->capacity;

    if (out_len) {
        *out_len = cap - head;
    }

    return &ring->data[head];
}

void ipc_ring_advance(ipc_ring_t* ring, uint32_t len) {
    uint32_t head = atomic_load_explicit(&ring->head, memory_order_relaxed);
    uint32_t cap  = ring->capacity;

    uint32_t new_head = head + len;

    if (new_head >= cap) {
        new_head -= cap;
    }

    atomic_store_explicit(&ring->head, new_head, memory_order_release);
}