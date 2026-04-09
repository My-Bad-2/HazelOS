#ifndef KERNEL_SCHED_IPC_H
#define KERNEL_SCHED_IPC_H 1

#include <stdint.h>

#include "libs/dlist.h"
#include "libs/kobject.h"
#include "libs/spinlock.h"
#include "uapi/ipc.h"

#define IPC_MAX_MSG_REGS 4  // 4 registers * 8 bytes = 32 bytes

struct process;
struct thread;
struct syscall_regs;

struct ipc_msg_internal {
    struct dlist_head node;
    size_t data_len;
    size_t cap_count;
    uint32_t sender_badge;

    // Dynamic memory layout follows as:
    // [ uint8_t data[data_len] ]
    // [ struct capability* cap_objects[cap_count] ]
    // [ struct cap_disp user_disps[cap_count] ]
};

struct ipc_port_object {
    struct dlist_head port_node;
    uint64_t user_key;
    uint32_t pending_signals;
    bool in_port;
};

struct ipc_port {
    struct kobject refcount;
    qspinlock_t lock;
    struct dlist_head event_queue;
    struct dlist_head waiters;
};

struct ipc_endpoint {
    struct kobject refcount;
    qspinlock_t lock;

    struct ipc_endpoint* peer;
    bool peer_closed;

    struct ipc_port* bound_port;
    struct ipc_port_object port_state;

    struct dlist_head msg_queue;
    struct dlist_head blocked_receivers;
};

struct thread_ipc_state {
    int status;
    struct ipc_msg_internal* rpc_reply_msg;
};

void ipc_init(void);

int sys_endpoint_create(uint64_t* cap0_out, uint64_t* cap1_out);
int sys_port_create(uint64_t* cap_out);
int sys_port_bind(uint64_t port_cap, uint64_t ep_cap, uint64_t key);
int sys_port_wait(uint64_t port_cap, struct port_event* out_event, int timeout_ms);

int sys_channel_write(uint64_t ep_cap_id, struct ipc_msg* msg);
int sys_channel_read(uint64_t ep_cap_id, struct ipc_msg* msg, uint32_t* badge_out, int timeout_ms);
int sys_channel_call(uint64_t ep_cap_id, struct ipc_msg* tx, struct ipc_msg* rx, int timeout_ms);

void ipc_endpoint_release(struct kobject* ref);
void ipc_port_release(struct kobject* ref);

#endif