#ifndef KERNEL_SCHED_IPC_H
#define KERNEL_SCHED_IPC_H 1

#include "libs/dlist.h"
#include "libs/spinlock.h"
#include "uapi/ipc.h"

struct process;
struct thread;

typedef enum { OBJ_CHANNEL, OBJ_PORT_SET } ipc_obj_type_t;

typedef struct {
    ipc_obj_type_t type;
    atomic_int ref_count;
    spinlock_t lock;
} ipc_object_t;

typedef struct ipc_channel {
    ipc_object_t header;

    struct ipc_channel* peer;  // The other end of the pipe
    struct ipc_port_set* wait_set;
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
} ipc_kernel_event_t;

int sys_ipc_create_channel(int32_t* handles_out, uintptr_t* ring_vaddr_out);
int sys_ipc_create_port_set(int32_t* handle_out);
int sys_ipc_bind(int32_t port_handle, int32_t chan_handle, uint64_t key);
int sys_ipc_notify(int32_t chan_handle);
int sys_ipc_wait(int32_t port_handle, ipc_event_t* out_event, int timeout_ms);
void sys_ipc_close(int32_t handle);

#endif