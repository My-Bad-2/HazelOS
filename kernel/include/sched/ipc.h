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

    // Rendezvous Queues: Hold blocked threads
    struct dlist_head blocked_senders;
    struct dlist_head blocked_receivers;
    struct dlist_head port_node;

    bool peer_closed;
    bool is_in_port_set;
};

struct thread_ipc_state {
    int status;
    bool use_memory;

    struct ipc_msg_info msg_info;
    uint64_t msg_regs[IPC_MAX_MSG_REGS];
    uint32_t sender_badge;
};

void ipc_init(void);

int sys_ipc_create_channel(uint64_t* cap_id_out);
int sys_ipc_port_create(uint64_t* cap_id_out);
int sys_ipc_bind(uint64_t port_cap_id, uint64_t chan_cap_id, uint64_t key);
int sys_ipc_wait(uint64_t port_cap_id, struct ipc_event* out_event, int timeout_ms);
int sys_ipc_close(uint64_t handle);

int sys_ipc_call(
    uint64_t chan_cap_id,
    struct ipc_msg_info* send_info,
    struct ipc_msg_info* recv_info,
    struct syscall_regs* regs
);
int sys_ipc_send(uint64_t chan_cap_id, struct ipc_msg_info* info, struct syscall_regs* regs);
int sys_ipc_recv(uint64_t chan_cap_id, struct ipc_msg_info* info, struct syscall_regs* regs);

void arch_sys_ipc_send(struct syscall_regs* regs, struct thread_ipc_state* state);
void arch_sys_ipc_recv(struct syscall_regs* regs, struct thread_ipc_state* state);

#endif