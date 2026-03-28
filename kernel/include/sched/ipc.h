#include "libs/kobject.h"
#ifndef KERNEL_SCHED_IPC_H
#define KERNEL_SCHED_IPC_H 1

#include <stdint.h>

#include "libs/dlist.h"
#include "libs/spinlock.h"
#include "uapi/ipc.h"

#define IPC_MAX_MSG_REGS 4  // 4 registers * 8 bytes = 32 bytes

struct process;
struct thread;
struct syscall_regs;

typedef enum {
    OBJ_CHANNEL,
    OBJ_NOTIFICATION,
    OBJ_PORT_SET,
    OBJ_ANY,
} ipc_obj_type_t;

struct ipc_object_header {
    int type;
    bool is_in_port_set;
    struct dlist_head port_node;
    uint64_t user_key;
};

struct ipc_port_set {
    struct kobject refcount;
    qspinlock_t lock;

    struct dlist_head event_queue;
    struct dlist_head waiters;
};

struct ipc_notification {
    struct ipc_object_header header;
    struct kobject refcount;
    qspinlock_t lock;

    uint64_t state;
    struct ipc_port_set* wait_set;
};

struct ipc_channel {
    struct ipc_object_header header;

    struct kobject refcount;
    bool peer_closed;
    qspinlock_t lock;

    struct ipc_channel* peer;
    struct ipc_port_set* wait_set;

    // Rendezvous Queues
    struct dlist_head blocked_senders;
    struct dlist_head blocked_receivers;
};

struct thread_ipc_state {
    int status;
    bool use_memory;
    bool is_doing_call;

    struct ipc_msg_info msg_info;
    uint64_t msg_regs[IPC_MAX_MSG_REGS];
    uint32_t sender_badge;
};

void ipc_init(void);

int sys_ipc_create_channel(uint64_t* cap_id_out);
int sys_ipc_port_create(uint64_t* cap_id_out);
int sys_ipc_notification_create(uint64_t* cap_id_out);

int sys_ipc_bind(uint64_t port_cap_id, uint64_t chan_cap_id, uint64_t key);
int sys_ipc_wait(uint64_t port_cap_id, struct ipc_event* out_event, int timeout_ms);
int sys_ipc_notify(uint64_t notif_cap_id, uint64_t bits);

int sys_ipc_send(
    uint64_t chan_cap_id,
    struct ipc_msg_info* info,
    int timeout_ms,
    struct syscall_regs* regs
);
int sys_ipc_recv(
    uint64_t chan_cap_id,
    struct ipc_msg_info* info,
    int timeout_ms,
    struct syscall_regs* regs
);
int sys_ipc_call(
    uint64_t chan_cap_id,
    struct ipc_msg_info* send_info,
    struct ipc_msg_info* recv_info,
    int timeout_ms,
    struct syscall_regs* regs
);

void arch_sys_ipc_send(struct syscall_regs* regs, struct thread_ipc_state* state);
void arch_sys_ipc_recv(struct syscall_regs* regs, struct thread_ipc_state* state);

void ipc_channel_release(struct kobject* ref);
void ipc_port_set_release(struct kobject* ref);
void ipc_notification_release(struct kobject* ref);

#endif