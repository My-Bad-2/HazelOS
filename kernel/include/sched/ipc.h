#ifndef KERNEL_SCHED_IPC_H
#define KERNEL_SCHED_IPC_H 1

#include <stdint.h>

#include "cpu/exception.h"
#include "libs/dlist.h"
#include "libs/kobject.h"
#include "libs/spinlock.h"

#define IPC_MAX_MSG_REGS 4  // 4 registers * 8 bytes = 32 bytes

#define IPC_MAX_QUEUE_BYTES (64ul * 1024)  // 64 KB max data per channel
#define IPC_MAX_QUEUE_MSGS  128            // Max 128 discrete messages

struct process;
struct thread;

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
    uint32_t signal_count;

    bool in_port;

    // Level-triggerred events remain READABLE as long as there is a message in the queue.
    // Edge-triggered events should be cleared the moment the userspace thread acknowledges it, and
    // we need to count how many times the edge was hit before it was acknowledged
    bool auto_clear;
    uint32_t type;
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

    struct dlist_head blocked_senders;
    size_t current_queue_bytes;
    size_t current_msg_count;
    size_t max_queue_bytes;
    size_t max_msg_count;
};

struct thread_ipc_state {
    int status;
    struct ipc_msg_internal* rpc_reply_msg;
};

struct kernel_page_request {
    struct ipc_port_object port_obj;
    size_t offset;
    size_t cluster_size;
    struct thread* faulting_thread;
};

void ipc_init(void);
void port_notify(struct ipc_port* port, struct ipc_port_object* obj, uint32_t signals);

uint64_t sys_endpoint_create(struct interrupt_trapframe* regs);
uint64_t sys_port_create(struct interrupt_trapframe* regs);
uint64_t sys_port_bind(struct interrupt_trapframe* regs);
uint64_t sys_port_wait(struct interrupt_trapframe* regs);

uint64_t sys_channel_write(struct interrupt_trapframe* regs);
uint64_t sys_channel_read(struct interrupt_trapframe* regs);
uint64_t sys_channel_call(struct interrupt_trapframe* regs);
uint64_t sys_channel_forward(struct interrupt_trapframe* regs);

void ipc_endpoint_release(struct kobject* ref);
void ipc_port_release(struct kobject* ref);
void ipc_send_page_request(
    struct ipc_port* port,
    uint64_t pager_key,
    size_t offset,
    size_t cluster_size
);

#endif