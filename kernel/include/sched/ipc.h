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

#define IPC_RIGHTS_ALL UINT32_MAX
#define IPC_RIGHTS_READ_ONLY \
    (IPC_RIGHT_READ | IPC_RIGHT_TRANSFER | IPC_RIGHT_MAP | IPC_RIGHT_DUPLICATE | IPC_RIGHT_INSPECT)
#define IPC_RIGHTS_WRITE_ONLY (IPC_RIGHT_WRITE | IPC_RIGHT_TRANSFER | IPC_RIGHT_INSPECT)

#define IPC_MAX_MSG_HANDLES 8

struct process;
struct thread;

typedef enum {
    OBJ_CHANNEL,
    OBJ_PORT_SET,
    OBJ_ANY,
} ipc_obj_type_t;

typedef struct {
    ipc_obj_type_t type;
    atomic_int ref_count;
    qspinlock_t lock;
} ipc_object_t;

struct ipc_port_set {
    ipc_object_t header;
    struct dlist_head event_queue;
    struct dlist_head waiters;
};

struct ipc_channel {
    ipc_object_t header;

    struct ipc_channel* peer;  // The other end of the pipe
    struct ipc_port_set* wait_set;
    uint64_t user_key;
    bool peer_closed;

    // Rendezvous Queues: Hold blocked threads
    struct dlist_head blocked_senders;
    struct dlist_head blocked_receivers;

    struct dlist_head port_node;
    bool is_in_port_set;
};

struct thread_ipc_state {
    struct ipc_msg_info msg_info;
    int status;
};

void ipc_init(void);

int sys_ipc_create_channel(uint32_t* cap_id_out);
int sys_ipc_port_create(uint32_t* cap_id_out);
int sys_ipc_bind(uint32_t port_cap_id, uint32_t chan_cap_id, uint64_t key);
int sys_ipc_wait(uint32_t port_cap_id, struct ipc_event* out_event, int timeout_ms);
int sys_ipc_close(uint32_t handle);

int sys_ipc_call(
    uint32_t chan_cap_id,
    struct ipc_msg_info* send_info,
    struct ipc_msg_info* recv_info
);
int sys_ipc_send(uint32_t chan_cap_id, struct ipc_msg_info* info);
int sys_ipc_recv(uint32_t chan_cap_id, struct ipc_msg_info* info);

#endif