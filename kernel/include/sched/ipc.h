#ifndef KERNEL_SCHED_IPC_H
#define KERNEL_SCHED_IPC_H 1

#include <stdint.h>

#include "libs/dlist.h"
#include "libs/spinlock.h"
#include "uapi/ipc.h"

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

struct process;
struct thread;

typedef enum {
    OBJ_CHANNEL,
    OBJ_PORT_SET,
    OBJ_TIMER,
    OBJ_SHARED_MEM,
    OBJ_ANY,
} ipc_obj_type_t;

typedef struct {
    ipc_obj_type_t type;
    atomic_int ref_count;
    spinlock_t lock;
} ipc_object_t;

typedef struct ipc_channel {
    ipc_object_t header;

    struct ipc_channel* peer;  // The other end of the pipe
    struct ipc_port_set* wait_set;
    struct dlist_head handle_queue;
    uint64_t user_key;

    void* ring_buffer;
    bool peer_closed;
} ipc_channel_t;

struct thread_queue {
    struct dlist_head list;
};

typedef struct ipc_port_set {
    ipc_object_t header;

    struct dlist_head event_queue;
    struct thread_queue waiters;
} ipc_port_set_t;

typedef struct {
    struct dlist_head node;
    ipc_event_t data;
    bool is_embedded;
} ipc_kernel_event_t;

struct ipc_info {
    ipc_obj_type_t type;
    int32_t ref_count;
    uint32_t rights;

    union {
        struct {
            int32_t peer_handle;
            bool peer_alive;
            size_t queued_handles;
            uint64_t user_key;
        } channel;

        struct {
            size_t pending_events;
            size_t active_threads;
        } port_set;

        struct {
            size_t size_bytes;
            size_t page_count;
        } shm;

        struct {
            uint64_t deadline;
            bool is_periodic;
            bool is_active;
        } timer;
    };
};

int sys_ipc_create_channel(int32_t* handles_out, uintptr_t* ring_vaddr_out);
int sys_ipc_create_port_set(int32_t* handle_out);
void sys_ipc_close(int32_t handle);

int sys_ipc_bind(int32_t port_handle, int32_t chan_handle, uint64_t key);
int sys_ipc_notify(int32_t chan_handle);
int sys_ipc_wait(int32_t port_handle, ipc_event_t* out_event, int timeout_ms);

int sys_ipc_send_handles(int32_t chan_handle, int32_t* user_handles, size_t count);
int sys_ipc_recv_handles(int32_t chan_handle, int32_t* out_handles, size_t max_count);

int sys_ipc_inspect(int32_t handle, struct ipc_info* info);

int sys_ipc_timer_arm(
    int32_t port_handle,
    uint64_t user_key,
    uint64_t deadline_ms,
    int flags,
    int32_t* handle_out
);

int sys_ipc_shm_alloc(size_t size, int flags, int32_t* handle_out, uintptr_t* vaddr_out);

#endif