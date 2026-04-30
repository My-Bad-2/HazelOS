#include "sched/ipc.h"

#include <stdalign.h>
#include <stdatomic.h>
#include <stdint.h>
#include <string.h>

#include "compiler.h"
#include "core/capability.h"
#include "core/errors.h"
#include "core/syscalls.h"
#include "cpu/exception.h"
#include "cpu/smp.h"
#include "drivers/ktimer.h"
#include "libs/dlist.h"
#include "libs/spinlock.h"
#include "memory/heap.h"
#include "sched/process.h"
#include "sched/scheduler.h"
#include "uapi/ipc.h"

#define IPC_MAX_IOVECS      16u
#define IPC_WRITE_MSG_FLAGS (IPC_FLAG_IOVEC | IPC_FLAG_URGENT)
#define IPC_READ_MSG_FLAGS  (IPC_FLAG_PEEK)

static kmem_cache_t* endpoint_cache  = nullptr;
static kmem_cache_t* port_cache      = nullptr;
static kmem_cache_t* pager_req_cache = nullptr;

static inline thread_t* ipc_current_thread(void) {
    return smp_current_core()->curr_thread;
}

static inline process_t* ipc_current_process(void) {
    return ipc_current_thread()->owner;
}

static inline struct capability** ipc_msg_caps(struct ipc_msg_internal* kmsg) {
    return (struct capability**)((uint8_t*)(kmsg + 1) + kmsg->data_len);
}

static inline struct cap_disp* ipc_msg_disps(struct ipc_msg_internal* kmsg) {
    return (struct cap_disp*)(ipc_msg_caps(kmsg) + kmsg->cap_count);
}

static inline bool ipc_msg_size_overflow(size_t a, size_t b, size_t* out) {
    return add_overflow(a, b, out);
}

static bool ipc_kmsg_total_size(size_t data_len, size_t cap_count, size_t* out_total_size) {
    size_t caps_size;
    size_t disp_size;
    size_t payload_size;

    if (mul_overflow(cap_count, sizeof(struct capability*), &caps_size)) return false;
    if (mul_overflow(cap_count, sizeof(struct cap_disp), &disp_size)) return false;
    if (ipc_msg_size_overflow(sizeof(struct ipc_msg_internal), data_len, &payload_size))
        return false;
    if (ipc_msg_size_overflow(payload_size, caps_size, &payload_size)) return false;
    if (ipc_msg_size_overflow(payload_size, disp_size, &payload_size)) return false;

    *out_total_size = payload_size;
    return true;
}

static inline void ipc_release_cap_refs(struct ipc_msg_internal* kmsg, size_t count) {
    struct capability** caps = ipc_msg_caps(kmsg);

    for (size_t i = 0; i < count; ++i) {
        struct capability* cap = caps[i];
        if (!cap) continue;

        void* obj = (void*)atomic_load_explicit(&cap->object_ptr, memory_order_acquire);
        cap_object_unref(cap->type, obj);
    }
}

static inline void ipc_destroy_kmsg(struct ipc_msg_internal* kmsg) {
    if (!kmsg) return;

    ipc_release_cap_refs(kmsg, kmsg->cap_count);
    kfree(kmsg);
}

static int ipc_validate_write_msg(const struct ipc_msg* msg) {
    if (msg->flags & ~(uint32_t)IPC_WRITE_MSG_FLAGS) return ERR_INVALID;
    if (msg->cap_count > 0 && !msg->caps) return ERR_INVALID;
    if (msg->data_len > 0 && !msg->data) return ERR_INVALID;
    if ((msg->flags & IPC_FLAG_IOVEC) && msg->data_len > IPC_MAX_IOVECS) return ERR_INVALID;
    return ERR_OK;
}

static int ipc_validate_read_msg(const struct ipc_msg* msg) {
    if (msg->flags & ~(uint32_t)IPC_READ_MSG_FLAGS) return ERR_INVALID;
    if (msg->data_len > 0 && !msg->data) return ERR_INVALID;
    if (msg->cap_count > 0 && !msg->caps) return ERR_INVALID;
    return ERR_OK;
}

static inline void ipc_wake_one_receiver(struct dlist_head* waiters) {
    if (dlist_empty(waiters)) return;

    thread_t* t = dlist_entry(waiters->next, thread_t, wait_node);
    dlist_del(&t->wait_node);
    t->ipc_state.status = ERR_OK;
    scheduler_unblock(t);
}

static inline void ipc_endpoint_init(struct ipc_endpoint* ep) {
    memset(ep, 0, sizeof(*ep));
    kref_init(&ep->refcount, CAP_TYPE_ENDPOINT);
    create_qspinlock(&ep->lock);

    dlist_init(&ep->msg_queue);
    dlist_init(&ep->blocked_receivers);
    dlist_init(&ep->blocked_senders);

    ep->port_state.auto_clear = IPC_EVENT_LEVEL_TRIGGERED;
    ep->max_queue_bytes       = IPC_MAX_QUEUE_BYTES;
    ep->max_msg_count         = IPC_MAX_QUEUE_MSGS;
}

static inline void ipc_port_init(struct ipc_port* port) {
    memset(port, 0, sizeof(*port));
    kref_init(&port->refcount, CAP_TYPE_PORT);
    create_qspinlock(&port->lock);
    dlist_init(&port->event_queue);
    dlist_init(&port->waiters);
}

static void ipc_close_cap_range(process_t* proc, struct cap_disp* disps, size_t count) {
    for (size_t i = 0; i < count; ++i)
        if (disps[i].cap_id != 0) cap_close(proc->root_cnode, disps[i].cap_id);
}

static inline void
ipc_queue_message(struct ipc_endpoint* peer, struct ipc_msg_internal* kmsg, bool urgent) {
    if (urgent)
        dlist_add(&kmsg->node, &peer->msg_queue);
    else
        dlist_add_tail(&kmsg->node, &peer->msg_queue);

    port_notify(peer->bound_port, &peer->port_state, IPC_SIGNAL_READABLE);
    ipc_wake_one_receiver(&peer->blocked_receivers);
}

void ipc_init(void) {
    endpoint_cache = kmem_cache_create(
        "ipc_endpoint",
        sizeof(struct ipc_endpoint),
        _Alignof(struct ipc_endpoint),
        0,
        nullptr
    );

    port_cache = kmem_cache_create(
        "ipc_port",
        sizeof(struct ipc_port),
        _Alignof(struct ipc_port),
        0,
        nullptr
    );

    pager_req_cache = kmem_cache_create(
        "pager_req",
        sizeof(struct kernel_page_request),
        _Alignof(struct kernel_page_request),
        0,
        nullptr
    );

    ktimer_init();
}

void port_notify(struct ipc_port* port, struct ipc_port_object* obj, uint32_t signals) {
    if (!port) return;

    acquire_qspinlock(&port->lock);
    obj->pending_signals |= signals;
    obj->signal_count++;  // Tracks the overrun/message count

    if (!obj->in_port) {
        obj->in_port = true;
        dlist_add_tail(&obj->port_node, &port->event_queue);

        if (!dlist_empty(&port->waiters)) {
            thread_t* t = dlist_entry(port->waiters.next, thread_t, wait_node);
            dlist_del_init(&t->wait_node);
            scheduler_unblock(t);
        }
    }

    release_qspinlock(&port->lock);
}

static int
msg_extract_caps(process_t* proc, struct ipc_msg* user_msg, struct ipc_msg_internal* kmsg) {
    if (kmsg->cap_count == 0) return ERR_OK;

    struct capability** kmsg_objects = ipc_msg_caps(kmsg);
    struct cap_disp* kmsg_disps      = ipc_msg_disps(kmsg);

    if (copy_from_user(kmsg_disps, user_msg->caps, sizeof(struct cap_disp) * kmsg->cap_count) !=
        ERR_OK)
        return ERR_FAULT;

    for (size_t i = 0; i < kmsg->cap_count; i++) {
        if (kmsg_disps[i].op != IPC_CAP_OP_COPY && kmsg_disps[i].op != IPC_CAP_OP_MOVE) {
            ipc_release_cap_refs(kmsg, i);
            return ERR_INVALID;
        }

        uint64_t cid = kmsg_disps[i].cap_id;

        struct capability* src_cap = cap_lookup(proc->root_cnode, cid, kmsg_disps[i].rights);
        if (!src_cap) {
            ipc_release_cap_refs(kmsg, i);
            return ERR_INVALID_CAP;
        }

        void* obj = (void*)atomic_load_explicit(&src_cap->object_ptr, memory_order_acquire);
        cap_object_ref(src_cap->type, obj);

        kmsg_objects[i] = src_cap;

        if (kmsg_disps[i].op == IPC_CAP_OP_MOVE && cap_close(proc->root_cnode, cid) != ERR_OK) {
            ipc_release_cap_refs(kmsg, i + 1);
            return ERR_INVALID_CAP;
        }
    }

    return ERR_OK;
}

static int
msg_install_caps(process_t* proc, struct ipc_msg_internal* kmsg, struct ipc_msg* user_msg) {
    if (kmsg->cap_count == 0) return ERR_OK;

    struct capability** kmsg_objects = ipc_msg_caps(kmsg);
    struct cap_disp* kmsg_disps      = ipc_msg_disps(kmsg);
    size_t created_caps              = 0;

    for (size_t i = 0; i < kmsg->cap_count; i++) {
        struct capability* src_data = kmsg_objects[i];

        uint64_t new_cap_id;
        struct capability* new_cap = cap_alloc(proc->root_cnode, &new_cap_id);

        if (new_cap) {
            void* obj = (void*)atomic_load_explicit(&src_data->object_ptr, memory_order_acquire);
            atomic_store_explicit(&new_cap->object_ptr, (uintptr_t)obj, memory_order_release);

            new_cap->type   = src_data->type;
            new_cap->rights = src_data->rights & kmsg_disps[i].rights;
            new_cap->badge  = src_data->badge;

            kmsg_disps[i].cap_id = new_cap_id;
            created_caps++;
        } else {
            ipc_close_cap_range(proc, kmsg_disps, created_caps);
            return ERR_NO_MEM;
        }
    }

    if (copy_to_user(user_msg->caps, kmsg_disps, sizeof(struct cap_disp) * kmsg->cap_count) !=
        ERR_OK) {
        ipc_close_cap_range(proc, kmsg_disps, kmsg->cap_count);
        return ERR_FAULT;
    }

    return ERR_OK;
}

void ipc_endpoint_release(struct kobject* ref) {
    struct ipc_endpoint* ep = kref_entry(ref, struct ipc_endpoint, refcount);
    acquire_qspinlock(&ep->lock);

    if (ep->peer) {
        acquire_qspinlock(&ep->peer->lock);

        ep->peer->peer        = nullptr;
        ep->peer->peer_closed = true;

        thread_t *t, *n;
        dlist_for_each_entry_safe(t, n, &ep->peer->blocked_receivers, wait_node) {
            dlist_del(&t->wait_node);
            t->ipc_state.status = ERR_IPC_DISCONNECT;
            scheduler_unblock(t);
        }

        port_notify(ep->peer->bound_port, &ep->peer->port_state, IPC_SIGNAL_PEER_CLOSED);
        release_qspinlock(&ep->peer->lock);
    }

    struct ipc_msg_internal *msg, *msg_n;
    dlist_for_each_entry_safe(msg, msg_n, &ep->msg_queue, node) {
        dlist_del(&msg->node);

        ipc_destroy_kmsg(msg);
    }

    release_qspinlock(&ep->lock);

    if (ep->bound_port) kref_put(&ep->bound_port->refcount, ipc_port_release);
    kmem_cache_free(endpoint_cache, ep);
}

void ipc_port_release(struct kobject* ref) {
    struct ipc_port* port = kref_entry(ref, struct ipc_port, refcount);

    thread_t *t, *n;
    dlist_for_each_entry_safe(t, n, &port->waiters, wait_node) {
        dlist_del(&t->wait_node);
        t->ipc_state.status = ERR_IPC_ABORTED;
        scheduler_unblock(t);
    }

    kmem_cache_free(port_cache, port);
}

uint64_t sys_endpoint_create(struct interrupt_trapframe* regs) {
    uint64_t* cap0_out = (uint64_t*)SYSCALL_FIRST_ARG(regs);
    uint64_t* cap1_out = (uint64_t*)SYSCALL_SECOND_ARG(regs);

    process_t* proc = ipc_current_process();

    struct ipc_endpoint* ep0 = kmem_cache_alloc(endpoint_cache);
    struct ipc_endpoint* ep1 = kmem_cache_alloc(endpoint_cache);

    if (!ep0 || !ep1) {
        if (ep0) kmem_cache_free(endpoint_cache, ep0);
        if (ep1) kmem_cache_free(endpoint_cache, ep1);
        return (uint64_t)ERR_NO_MEM;
    }

    ipc_endpoint_init(ep0);
    ipc_endpoint_init(ep1);

    ep0->peer = ep1;
    ep1->peer = ep0;

    uint64_t cap0, cap1;
    struct capability* c0 = cap_alloc(proc->root_cnode, &cap0);
    struct capability* c1 = cap_alloc(proc->root_cnode, &cap1);

    if (!c0 || !c1) {
        if (c0) cap_close(proc->root_cnode, cap0);
        if (c1) cap_close(proc->root_cnode, cap1);
        kmem_cache_free(endpoint_cache, ep0);
        kmem_cache_free(endpoint_cache, ep1);
        return (uint64_t)ERR_NO_MEM;
    }

    atomic_store_explicit(&c0->object_ptr, (uintptr_t)ep0, memory_order_release);
    c0->type   = CAP_TYPE_ENDPOINT;
    c0->rights = RIGHT_ALL;

    atomic_store_explicit(&c1->object_ptr, (uintptr_t)ep1, memory_order_release);
    c1->type   = CAP_TYPE_ENDPOINT;
    c1->rights = RIGHT_ALL;

    if (!write_cap_out(cap0_out, cap0) || !write_cap_out(cap1_out, cap1)) {
        cap_close(proc->root_cnode, cap0);
        cap_close(proc->root_cnode, cap1);
        return (uint64_t)ERR_FAULT;
    }

    return ERR_OK;
}

uint64_t sys_port_create(struct interrupt_trapframe* regs) {
    uint64_t* cap_out = (uint64_t*)SYSCALL_FIRST_ARG(regs);

    process_t* proc = ipc_current_process();

    struct ipc_port* port = kmem_cache_alloc(port_cache);
    if (!port) return (uint64_t)ERR_NO_MEM;

    ipc_port_init(port);

    uint64_t cap;
    struct capability* c = cap_alloc(proc->root_cnode, &cap);
    if (!c) {
        kmem_cache_free(port_cache, port);
        return (uint64_t)ERR_NO_MEM;
    }

    atomic_store_explicit(&c->object_ptr, (uintptr_t)port, memory_order_release);
    c->type   = CAP_TYPE_PORT;
    c->rights = RIGHT_ALL;

    if (!write_cap_out(cap_out, cap)) {
        cap_close(proc->root_cnode, cap);
        return (uint64_t)ERR_FAULT;
    }

    return ERR_OK;
}

uint64_t sys_port_bind(struct interrupt_trapframe* regs) {
    const uint64_t port_cap   = SYSCALL_FIRST_ARG(regs);
    const uint64_t target_cap = SYSCALL_SECOND_ARG(regs);
    const uint64_t key        = SYSCALL_THIRD_ARG(regs);

    process_t* proc = ipc_current_process();

    struct capability* p_cap = cap_lookup(proc->root_cnode, port_cap, RIGHT_WRITE);
    struct capability* t_cap = cap_lookup(proc->root_cnode, target_cap, RIGHT_WRITE);

    if (!p_cap || !t_cap || p_cap->type != CAP_TYPE_PORT) return (uint64_t)ERR_INVALID_CAP;

    struct ipc_port* port =
        (struct ipc_port*)atomic_load_explicit(&p_cap->object_ptr, memory_order_acquire);

    if (t_cap->type == CAP_TYPE_ENDPOINT) {
        struct ipc_endpoint* ep =
            (struct ipc_endpoint*)atomic_load_explicit(&t_cap->object_ptr, memory_order_acquire);

        acquire_qspinlock(&ep->lock);

        if (ep->bound_port) kref_put(&ep->bound_port->refcount, ipc_port_release);
        kref_get(&port->refcount);
        ep->bound_port          = port;
        ep->port_state.user_key = key;
        uint32_t signals        = 0;
        if (!dlist_empty(&ep->msg_queue)) signals |= IPC_SIGNAL_READABLE;
        if (ep->peer_closed) signals |= IPC_SIGNAL_PEER_CLOSED;

        if (signals) port_notify(port, &ep->port_state, signals);

        release_qspinlock(&ep->lock);
        return ERR_OK;
    } else if (t_cap->type == CAP_TYPE_TIMER) {
        struct kernel_timer* timer =
            (struct kernel_timer*)atomic_load_explicit(&t_cap->object_ptr, memory_order_acquire);

        acquire_qspinlock(&timer->lock);
        if (timer->bound_port) kref_put(&timer->bound_port->refcount, ipc_port_release);
        kref_get(&port->refcount);

        timer->bound_port          = port;
        timer->port_state.user_key = key;
        release_qspinlock(&timer->lock);
        return ERR_OK;
    }

    return (uint64_t)ERR_INVALID_CAP;
}

uint64_t sys_channel_write(struct interrupt_trapframe* regs) {
    const uint64_t ep_cap_id       = SYSCALL_FIRST_ARG(regs);
    const struct ipc_msg* user_msg = (struct ipc_msg*)SYSCALL_SECOND_ARG(regs);
    const int timeout_ms           = SYSCALL_THIRD_ARG(regs);

    struct ipc_msg msg;
    if (copy_from_user(&msg, user_msg, sizeof(struct ipc_msg)) != ERR_OK)
        return (uint64_t)ERR_FAULT;

    int validation_err = ipc_validate_write_msg(&msg);
    if (validation_err != ERR_OK) return (uint64_t)validation_err;

    process_t* proc = ipc_current_process();

    struct capability* cap = cap_lookup(proc->root_cnode, ep_cap_id, RIGHT_WRITE);
    if (!cap) return (uint64_t)ERR_INVALID_CAP;

    if (cap->type == CAP_TYPE_REPLY) {
        thread_t* target_thread =
            (thread_t*)atomic_load_explicit(&cap->object_ptr, memory_order_acquire);

        size_t total_size;
        if (!ipc_kmsg_total_size(msg.data_len, msg.cap_count, &total_size))
            return (uint64_t)ERR_INVALID;

        struct ipc_msg_internal* kmsg = kmalloc(total_size);
        if (!kmsg) return (uint64_t)ERR_NO_MEM;

        kmsg->data_len  = msg.data_len;
        kmsg->cap_count = msg.cap_count;
        if (msg.data_len > 0 &&
            copy_from_user((void*)(kmsg + 1), msg.data, msg.data_len) != ERR_OK) {
            kfree(kmsg);
            return (uint64_t)ERR_FAULT;
        }

        int err = msg_extract_caps(proc, &msg, kmsg);
        if (err != ERR_OK) {
            kfree(kmsg);
            return (uint64_t)err;
        }

        target_thread->ipc_state.rpc_reply_msg = kmsg;
        target_thread->ipc_state.status        = ERR_OK;
        scheduler_unblock(target_thread);

        cap_close(proc->root_cnode, ep_cap_id);
        return ERR_OK;
    }

    size_t total_data_bytes = 0;
    struct ipc_iovec iovs[IPC_MAX_IOVECS];

    if (msg.flags & IPC_FLAG_IOVEC) {
        if (copy_from_user(iovs, msg.data, msg.data_len * sizeof(struct ipc_iovec)) != ERR_OK)
            return (uint64_t)ERR_FAULT;

        for (size_t i = 0; i < msg.data_len; ++i) {
            if (iovs[i].len > 0 && !iovs[i].base) return (uint64_t)ERR_INVALID;
            if (add_overflow(total_data_bytes, iovs[i].len, &total_data_bytes))
                return (uint64_t)ERR_INVALID;
        }
    } else {
        total_data_bytes = msg.data_len;
    }

    if (unlikely(cap->type != CAP_TYPE_ENDPOINT)) return (uint64_t)ERR_INVALID_CAP;

    size_t total_size;
    if (!ipc_kmsg_total_size(total_data_bytes, msg.cap_count, &total_size))
        return (uint64_t)ERR_INVALID;

    struct ipc_msg_internal* kmsg = kmalloc(total_size);
    if (!kmsg) return (uint64_t)ERR_NO_MEM;

    kmsg->data_len     = total_data_bytes;
    kmsg->cap_count    = msg.cap_count;
    kmsg->sender_badge = cap->badge;

    uint8_t* kmsg_data = (uint8_t*)(kmsg + 1);
    if (msg.flags & IPC_FLAG_IOVEC) {
        size_t offset = 0;
        for (size_t i = 0; i < msg.data_len; ++i) {
            if (iovs[i].len > 0) {
                if (copy_from_user(kmsg_data + offset, iovs[i].base, iovs[i].len) != 0) {
                    kfree(kmsg);
                    return (uint64_t)ERR_FAULT;
                }

                offset += iovs[i].len;
            }
        }
    } else if (msg.data_len > 0) {
        if (copy_from_user(kmsg_data, msg.data, msg.data_len) != 0) {
            kfree(kmsg);
            return (uint64_t)ERR_FAULT;
        }
    }

    int err = msg_extract_caps(proc, &msg, kmsg);
    if (err != ERR_OK) {
        kfree(kmsg);
        return (uint64_t)err;
    }

    size_t payload_bytes = kmsg->data_len + (kmsg->cap_count * sizeof(uint64_t));

    struct ipc_endpoint* ep =
        (struct ipc_endpoint*)atomic_load_explicit(&cap->object_ptr, memory_order_acquire);

    size_t ep_flags           = acquire_qinterrupt_lock(&ep->lock);
    struct ipc_endpoint* peer = ep->peer;

    if (unlikely(!peer || ep->peer_closed)) {
        release_qinterrupt_lock(&ep->lock, ep_flags);
        ipc_destroy_kmsg(kmsg);
        return (uint64_t)ERR_IPC_DISCONNECT;
    }

    size_t peer_flags = acquire_qinterrupt_lock(&peer->lock);

    thread_t* me = smp_current_core()->curr_thread;
    while (peer->current_queue_bytes + payload_bytes > peer->max_queue_bytes ||
           peer->current_msg_count >= peer->max_msg_count) {
        if (timeout_ms == 0) {
            release_qinterrupt_lock(&peer->lock, peer_flags);
            release_qinterrupt_lock(&ep->lock, ep_flags);
            ipc_destroy_kmsg(kmsg);
            return (uint64_t)ERR_AGAIN;
        }

        dlist_add_tail(&me->wait_node, &peer->blocked_senders);

        release_qinterrupt_lock(&peer->lock, peer_flags);
        release_qinterrupt_lock(&ep->lock, ep_flags);

        if (timeout_ms > 0)
            scheduler_sleep(timeout_ms);
        else
            scheduler_block();

        ep_flags = acquire_qinterrupt_lock(&ep->lock);
        peer     = ep->peer;
        if (unlikely(!peer || ep->peer_closed)) {
            release_qinterrupt_lock(&ep->lock, ep_flags);
            ipc_destroy_kmsg(kmsg);
            return (uint64_t)ERR_IPC_DISCONNECT;
        }

        peer_flags = acquire_qinterrupt_lock(&peer->lock);

        if (dlist_linked(&me->wait_node)) {
            dlist_del_init(&me->wait_node);
            release_qinterrupt_lock(&peer->lock, peer_flags);
            release_qinterrupt_lock(&ep->lock, ep_flags);
            ipc_destroy_kmsg(kmsg);
            return (uint64_t)ERR_TIMEOUT;
        }
    }

    peer->current_queue_bytes += payload_bytes;
    peer->current_msg_count++;

    ipc_queue_message(peer, kmsg, (msg.flags & IPC_FLAG_URGENT) != 0);

    release_qinterrupt_lock(&peer->lock, peer_flags);
    release_qinterrupt_lock(&ep->lock, ep_flags);

    return ERR_OK;
}

uint64_t sys_channel_read(struct interrupt_trapframe* regs) {
    uint64_t ep_cap_id       = SYSCALL_FIRST_ARG(regs);
    struct ipc_msg* user_msg = (struct ipc_msg*)SYSCALL_SECOND_ARG(regs);
    uint32_t* badge_out      = (uint32_t*)SYSCALL_THIRD_ARG(regs);
    int timeout_ms           = SYSCALL_FOURTH_ARG(regs);

    struct ipc_msg msg;
    if (copy_from_user(&msg, user_msg, sizeof(struct ipc_msg)) != ERR_OK)
        return (uint64_t)ERR_FAULT;

    int validation_err = ipc_validate_read_msg(&msg);
    if (validation_err != ERR_OK) return (uint64_t)validation_err;

    thread_t* me    = ipc_current_thread();
    process_t* proc = me->owner;

    struct capability* cap = cap_lookup(proc->root_cnode, ep_cap_id, RIGHT_READ);
    if (unlikely(!cap || cap->type != CAP_TYPE_ENDPOINT)) return (uint64_t)ERR_INVALID_CAP;

    struct ipc_endpoint* ep =
        (struct ipc_endpoint*)atomic_load_explicit(&cap->object_ptr, memory_order_acquire);

    acquire_qspinlock(&ep->lock);

    while (dlist_empty(&ep->msg_queue)) {
        if (ep->peer_closed) {
            release_qspinlock(&ep->lock);
            return (uint64_t)ERR_IPC_DISCONNECT;
        }

        if (timeout_ms == 0) {
            release_qspinlock(&ep->lock);
            return (uint64_t)ERR_AGAIN;
        }

        dlist_add_tail(&me->wait_node, &ep->blocked_receivers);

        release_qspinlock(&ep->lock);

        if (timeout_ms > 0)
            scheduler_sleep(timeout_ms);
        else
            scheduler_block();

        acquire_qspinlock(&ep->lock);

        if (dlist_linked(&me->wait_node)) {
            dlist_del_init(&me->wait_node);
            release_qspinlock(&ep->lock);
            return (uint64_t)ERR_TIMEOUT;
        }

        if (me->ipc_state.status == ERR_IPC_DISCONNECT && dlist_empty(&ep->msg_queue)) {
            release_qspinlock(&ep->lock);
            return (uint64_t)ERR_IPC_DISCONNECT;
        }
    }

    struct ipc_msg_internal* kmsg = dlist_entry(ep->msg_queue.next, struct ipc_msg_internal, node);
    size_t payload_bytes          = kmsg->data_len + (kmsg->cap_count * sizeof(uint64_t));

    if (msg.flags & IPC_FLAG_PEEK) {
        release_qspinlock(&ep->lock);

        msg.data_len  = kmsg->data_len;
        msg.cap_count = kmsg->cap_count;
        if (copy_to_user(user_msg, &msg, sizeof(struct ipc_msg)) != ERR_OK)
            return (uint64_t)ERR_FAULT;

        return ERR_OK;
    }

    if (msg.data_len < kmsg->data_len || msg.cap_count < kmsg->cap_count) {
        release_qspinlock(&ep->lock);

        msg.data_len  = kmsg->data_len;
        msg.cap_count = kmsg->cap_count;
        if (copy_to_user(user_msg, &msg, sizeof(struct ipc_msg)) != ERR_OK)
            return (uint64_t)ERR_FAULT;

        return (uint64_t)ERR_IPC_TRUNCATED;
    }

    dlist_del_init(&kmsg->node);

    ep->current_queue_bytes -= payload_bytes;
    ep->current_msg_count--;

    if (dlist_empty(&ep->msg_queue)) {
        ep->port_state.pending_signals &= ~IPC_SIGNAL_READABLE;
        ep->port_state.signal_count = 0;
    }

    if (!dlist_empty(&ep->blocked_senders)) {
        thread_t* t = dlist_entry(ep->blocked_senders.next, thread_t, wait_node);
        dlist_del_init(&t->wait_node);
        scheduler_unblock(t);
    }

    release_qspinlock(&ep->lock);

    void* kmsg_data = (void*)(kmsg + 1);
    if (kmsg->data_len > 0 && copy_to_user(msg.data, kmsg_data, kmsg->data_len) != ERR_OK) {
        kfree(kmsg);
        return (uint64_t)ERR_FAULT;
    }

    int install_err = msg_install_caps(proc, kmsg, &msg);
    if (install_err != ERR_OK) {
        kfree(kmsg);
        return (uint64_t)install_err;
    }

    if (badge_out && copy_to_user(badge_out, &kmsg->sender_badge, sizeof(uint32_t)) != ERR_OK) {
        kfree(kmsg);
        return (uint64_t)ERR_FAULT;
    }

    msg.data_len  = kmsg->data_len;
    msg.cap_count = kmsg->cap_count;
    if (copy_to_user(user_msg, &msg, sizeof(struct ipc_msg)) != ERR_OK) {
        kfree(kmsg);
        return (uint64_t)ERR_FAULT;
    }

    kfree(kmsg);
    return ERR_OK;
}

uint64_t sys_channel_call(struct interrupt_trapframe* regs) {
    struct ipc_msg* rx   = (struct ipc_msg*)SYSCALL_THIRD_ARG(regs);
    const int timeout_ms = SYSCALL_FOURTH_ARG(regs);

    thread_t* me    = ipc_current_thread();
    process_t* proc = me->owner;

    uint64_t reply_cap_id;
    struct capability* reply_cap = cap_alloc(proc->root_cnode, &reply_cap_id);
    if (!reply_cap) return (uint64_t)ERR_NO_MEM;

    atomic_store_explicit(&reply_cap->object_ptr, (uintptr_t)me, memory_order_release);
    reply_cap->type   = CAP_TYPE_REPLY;
    reply_cap->rights = RIGHT_WRITE;

    me->ipc_state.rpc_reply_msg = nullptr;

    uint64_t ret = sys_channel_write(regs);
    if (ret != ERR_OK) {
        cap_close(proc->root_cnode, reply_cap_id);
        return (uint64_t)ret;
    }

    if (timeout_ms > 0)
        scheduler_sleep(timeout_ms);
    else
        scheduler_block();

    cap_close(proc->root_cnode, reply_cap_id);

    if (me->ipc_state.rpc_reply_msg == nullptr) return (uint64_t)ERR_TIMEOUT;

    struct ipc_msg_internal* kmsg = me->ipc_state.rpc_reply_msg;
    struct ipc_msg msg;
    if (copy_from_user(&msg, rx, sizeof(struct ipc_msg)) != 0) {
        ipc_destroy_kmsg(kmsg);
        return (uint64_t)ERR_FAULT;
    }

    int validation_err = ipc_validate_read_msg(&msg);
    if (validation_err != ERR_OK) {
        ipc_destroy_kmsg(kmsg);
        return (uint64_t)validation_err;
    }

    if (msg.data_len < kmsg->data_len || msg.cap_count < kmsg->cap_count) {
        ipc_destroy_kmsg(kmsg);
        return (uint64_t)ERR_IPC_TRUNCATED;
    }

    if (kmsg->data_len > 0 && copy_to_user(msg.data, (void*)(kmsg + 1), kmsg->data_len) != ERR_OK) {
        ipc_destroy_kmsg(kmsg);
        return (uint64_t)ERR_FAULT;
    }

    int install_err = msg_install_caps(proc, kmsg, &msg);
    if (install_err != ERR_OK) {
        ipc_destroy_kmsg(kmsg);
        return (uint64_t)install_err;
    }

    msg.data_len  = kmsg->data_len;
    msg.cap_count = kmsg->cap_count;
    if (copy_to_user(rx, &msg, sizeof(struct ipc_msg)) != ERR_OK) {
        ipc_destroy_kmsg(kmsg);
        return (uint64_t)ERR_FAULT;
    }

    kfree(kmsg);
    return ERR_OK;
}

uint64_t sys_port_wait(struct interrupt_trapframe* regs) {
    const uint64_t port_cap       = SYSCALL_FIRST_ARG(regs);
    struct port_event* out_events = (struct port_event*)SYSCALL_SECOND_ARG(regs);
    const size_t max_events       = SYSCALL_THIRD_ARG(regs);
    size_t* events_returned       = (size_t*)SYSCALL_FOURTH_ARG(regs);
    const int timeout_ms          = SYSCALL_FIFTH_ARG(regs);

    thread_t* me    = ipc_current_thread();
    process_t* proc = me->owner;

    struct capability* p_cap = cap_lookup(proc->root_cnode, port_cap, RIGHT_WAIT);
    if (unlikely(!p_cap || p_cap->type != CAP_TYPE_PORT)) return (uint64_t)ERR_INVALID_CAP;

    struct ipc_port* set =
        (struct ipc_port*)atomic_load_explicit(&p_cap->object_ptr, memory_order_acquire);
    int ret      = ERR_OK;
    size_t count = 0;

    acquire_qspinlock(&set->lock);

    while (dlist_empty(&set->event_queue)) {
        if (timeout_ms == 0) {
            ret = ERR_AGAIN;
            break;
        }

        dlist_add_tail(&me->wait_node, &set->waiters);
        release_qspinlock(&set->lock);

        if (timeout_ms > 0)
            scheduler_sleep(timeout_ms);
        else
            scheduler_block();

        acquire_qspinlock(&set->lock);

        if (dlist_linked(&me->wait_node)) {
            dlist_del_init(&me->wait_node);
            if (dlist_empty(&set->event_queue)) {
                ret = ERR_TIMEOUT;
                break;
            }
        }
    }

    if (ret == ERR_OK) {
        struct dlist_head *curr, *next;
        dlist_for_each_safe(curr, next, &set->event_queue) {
            if (count >= max_events) break;

            struct ipc_port_object* obj = dlist_entry(curr, struct ipc_port_object, port_node);
            dlist_del_init(curr);
            obj->in_port = false;

            if (out_events) {
                struct port_event evt;
                evt.key  = obj->user_key;
                evt.type = obj->type;

                if (obj->type == IPC_PORT_TYPE_SIGNAL) {
                    evt.data.signal.signals = obj->pending_signals;
                    evt.data.signal.count   = obj->signal_count;

                    if (obj->auto_clear) {
                        obj->pending_signals = 0;
                        obj->signal_count    = 0;
                    }
                } else if (obj->type == IPC_PORT_TYPE_PAGER) {
                    struct kernel_page_request* req = (struct kernel_page_request*)obj;

                    evt.data.pager.offset = req->offset;
                    evt.data.pager.length = req->cluster_size;

                    kmem_cache_free(pager_req_cache, req);
                }

                if (copy_to_user(&out_events[count], &evt, sizeof(struct port_event)) != ERR_OK) {
                    ret = ERR_FAULT;
                    break;
                }
            }

            count++;
        }
    }

    release_qspinlock(&set->lock);

    if (events_returned && copy_to_user(events_returned, &count, sizeof(size_t)) != ERR_OK)
        return (uint64_t)ERR_FAULT;

    return (uint64_t)ret;
}

uint64_t sys_channel_forward(struct interrupt_trapframe* regs) {
    uint64_t src_ep_cap  = SYSCALL_FIRST_ARG(regs);
    uint64_t dest_ep_cap = SYSCALL_SECOND_ARG(regs);
    process_t* proc      = ipc_current_process();

    struct capability* cap_src = cap_lookup(proc->root_cnode, src_ep_cap, RIGHT_READ);
    struct capability* cap_dst = cap_lookup(proc->root_cnode, dest_ep_cap, RIGHT_WRITE);

    if (!cap_src || !cap_dst) return (uint64_t)ERR_INVALID_CAP;
    if (cap_src->type != CAP_TYPE_ENDPOINT || cap_dst->type != CAP_TYPE_ENDPOINT)
        return (uint64_t)ERR_INVALID_CAP;

    struct ipc_endpoint* ep_src =
        (struct ipc_endpoint*)atomic_load_explicit(&cap_src->object_ptr, memory_order_acquire);
    struct ipc_endpoint* ep_dst =
        (struct ipc_endpoint*)atomic_load_explicit(&cap_dst->object_ptr, memory_order_acquire);

    acquire_qspinlock(&ep_src->lock);
    if (dlist_empty(&ep_src->msg_queue)) {
        release_qspinlock(&ep_src->lock);
        return (uint64_t)ERR_AGAIN;
    }

    struct ipc_msg_internal* kmsg =
        dlist_entry(ep_src->msg_queue.next, struct ipc_msg_internal, node);
    dlist_del_init(&kmsg->node);

    if (dlist_empty(&ep_src->msg_queue)) ep_src->port_state.pending_signals &= ~IPC_SIGNAL_READABLE;

    release_qspinlock(&ep_src->lock);

    acquire_qspinlock(&ep_dst->lock);
    struct ipc_endpoint* peer = ep_dst->peer;

    if (unlikely(!peer || ep_dst->peer_closed)) {
        release_qspinlock(&ep_dst->lock);
        ipc_destroy_kmsg(kmsg);
        return (uint64_t)ERR_IPC_DISCONNECT;
    }

    acquire_qspinlock(&peer->lock);

    ipc_queue_message(peer, kmsg, false);

    release_qspinlock(&peer->lock);
    release_qspinlock(&ep_dst->lock);

    return ERR_OK;
}

void ipc_send_page_request(
    struct ipc_port* port,
    uint64_t pager_key,
    size_t offset,
    size_t cluster_size
) {
    if (unlikely(!port)) return;

    struct thread* me = smp_current_core()->curr_thread;

    struct kernel_page_request* req = kmem_cache_alloc(pager_req_cache);
    if (unlikely(!req)) thread_exit(ERR_NO_MEM);

    memset(req, 0, sizeof(struct kernel_page_request));
    dlist_init(&req->port_obj.port_node);

    req->port_obj.type     = IPC_PORT_TYPE_PAGER;
    req->port_obj.user_key = pager_key;

    req->offset          = offset;
    req->cluster_size    = cluster_size;
    req->faulting_thread = me;

    size_t flags = acquire_qinterrupt_lock(&port->lock);

    dlist_add_tail(&req->port_obj.port_node, &port->event_queue);
    req->port_obj.in_port = true;

    if (!dlist_empty(&port->waiters)) {
        struct thread* t = dlist_entry(port->waiters.next, struct thread, wait_node);
        dlist_del(&t->wait_node);
        scheduler_unblock(t);
    }

    release_qinterrupt_lock(&port->lock, flags);

    scheduler_block();
}