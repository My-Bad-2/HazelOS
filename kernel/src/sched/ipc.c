#include "sched/ipc.h"

#include <stdalign.h>
#include <stdatomic.h>
#include <stdint.h>
#include <string.h>

#include "compiler.h"
#include "core/capability.h"
#include "core/errors.h"
#include "cpu/smp.h"
#include "cpu/syscalls.h"
#include "libs/dlist.h"
#include "libs/handles.h"
#include "libs/spinlock.h"
#include "memory/heap.h"
#include "sched/process.h"
#include "sched/scheduler.h"
#include "sched/syscalls.h"
#include "uapi/ipc.h"

static kmem_cache_t* channel_cache = nullptr;
static kmem_cache_t* port_cache    = nullptr;

extern int copy_between_spaces(
    process_t* dest_proc,
    void* dest_addr,
    process_t* src_proc,
    const void* src_addr,
    size_t len
);

void ipc_init(void) {
    channel_cache = kmem_cache_create(
        "channel_cache",
        sizeof(struct ipc_channel),
        _Alignof(struct ipc_channel),
        0,
        nullptr
    );

    port_cache = kmem_cache_create(
        "port_cache",
        sizeof(struct ipc_port_set),
        _Alignof(struct ipc_port_set),
        0,
        nullptr
    );
}

static void sys_ipc_notify_internal(struct ipc_channel* dest) {
    struct ipc_port_set* set = dest->wait_set;
    if (!set) {
        return;
    }

    acquire_qspinlock(&set->header.lock);

    if (!dest->is_in_port_set) {
        dest->is_in_port_set = true;
        dlist_add_tail(&dest->port_node, &set->event_queue);

        // Wake up one waiting thread
        if (!dlist_empty(&set->waiters)) {
            struct dlist_head* first = set->waiters.next;
            thread_t* t              = dlist_entry(first, thread_t, wait_node);
            dlist_del(first);
            scheduler_unblock(t);
        }
    }

    release_qspinlock(&set->header.lock);
}

static void destroy_channel(struct ipc_channel* chan) {
    if (!chan) {
        return;
    }

    if (chan->peer) {
        acquire_qspinlock(&chan->peer->header.lock);
        chan->peer->peer        = nullptr;
        chan->peer->peer_closed = true;

        // Wake up anyone blocked waiting for the dead peer
        thread_t *t, *n;
        dlist_for_each_entry_safe(t, n, &chan->peer->blocked_senders, wait_node) {
            dlist_del(&t->wait_node);
            t->ipc_state.status = ERR_FAULT;
            scheduler_unblock(t);
        }

        dlist_for_each_entry_safe(t, n, &chan->peer->blocked_receivers, wait_node) {
            dlist_del(&t->wait_node);
            t->ipc_state.status = ERR_FAULT;
            scheduler_unblock(t);
        }

        sys_ipc_notify_internal(chan->peer);
        release_qspinlock(&chan->peer->header.lock);
    }

    // Cleanup any dangling threads in our own queues
    thread_t *t, *n;
    dlist_for_each_entry_safe(t, n, &chan->blocked_senders, wait_node) {
        dlist_del(&t->wait_node);
        t->ipc_state.status = ERR_FAULT;
        scheduler_unblock(t);
    }

    dlist_for_each_entry_safe(t, n, &chan->blocked_receivers, wait_node) {
        dlist_del(&t->wait_node);
        t->ipc_state.status = ERR_FAULT;
        scheduler_unblock(t);
    }

    // Unlink from our own port set
    if (chan->wait_set) {
        acquire_qspinlock(&chan->wait_set->header.lock);

        if (chan->is_in_port_set) {
            dlist_del(&chan->port_node);
        }

        release_qspinlock(&chan->wait_set->header.lock);
    }

    kmem_cache_free(channel_cache, chan);
}

int sys_ipc_create_channel(uint64_t* cap_id_out) {
    thread_t* me    = smp_current_core()->curr_thread;
    process_t* proc = me->owner;

    struct ipc_channel* ch1 = kmem_cache_alloc(channel_cache);
    if (!ch1) {
        return ERR_NO_MEM;
    }

    struct ipc_channel* ch2 = kmem_cache_alloc(channel_cache);
    if (!ch2) {
        kmem_cache_free(channel_cache, ch1);
        return ERR_NO_MEM;
    }

    memset(ch1, 0, sizeof(struct ipc_channel));
    memset(ch2, 0, sizeof(struct ipc_channel));

    ch1->header.type = OBJ_CHANNEL;
    create_qspinlock(&ch1->header.lock);
    dlist_init(&ch1->blocked_senders);
    dlist_init(&ch1->blocked_receivers);
    dlist_init(&ch1->port_node);

    ch2->header.type = OBJ_CHANNEL;
    create_qspinlock(&ch2->header.lock);
    dlist_init(&ch2->blocked_senders);
    dlist_init(&ch2->blocked_receivers);
    dlist_init(&ch2->port_node);

    ch1->peer = ch2;
    ch2->peer = ch1;

    uint64_t cap1, cap2;
    struct capability* c1 = cap_alloc(me->root_cnode, &cap1);
    struct capability* c2 = cap_alloc(me->root_cnode, &cap2);

    if (!c1 || !c2) {
        if (c1) {
            cap_revoke(me->root_cnode, c1);
        }

        kmem_cache_free(channel_cache, ch1);
        kmem_cache_free(channel_cache, ch2);
        return ERR_NO_MEM;
    }

    atomic_store_explicit(&c1->object_ptr, (uintptr_t)ch1, memory_order_release);
    c1->type   = CAP_TYPE_CHANNEL;
    c1->rights = RIGHT_ALL;

    atomic_store_explicit(&c2->object_ptr, (uintptr_t)ch2, memory_order_release);
    c2->type   = CAP_TYPE_CHANNEL;
    c2->rights = RIGHT_ALL;

    if (cap_id_out) {
        uint64_t out[2] = {cap1, cap2};
        copy_to_user(cap_id_out, out, sizeof(out));
    }

    return ERR_OK;
}

int sys_ipc_port_create(uint64_t* cap_id_out) {
    thread_t* me = smp_current_core()->curr_thread;

    struct ipc_port_set* set = kmem_cache_alloc(port_cache);
    if (!set) {
        return ERR_NO_MEM;
    }

    memset(set, 0, sizeof(struct ipc_port_set));
    set->header.type = OBJ_PORT_SET;
    create_qspinlock(&set->header.lock);
    dlist_init(&set->event_queue);
    dlist_init(&set->waiters);

    uint64_t cap         = 0;
    struct capability* c = cap_alloc(me->root_cnode, &cap);
    if (!c) {
        kmem_cache_free(port_cache, set);
        return ERR_NO_MEM;
    }

    atomic_store_explicit(&c->object_ptr, (uintptr_t)set, memory_order_release);
    c->type   = CAP_TYPE_PORT_SET;
    c->rights = RIGHT_ALL;

    if (cap_id_out) {
        copy_to_user(cap_id_out, &cap, sizeof(uint64_t));
    }

    return ERR_OK;
}

int sys_ipc_close(uint64_t cap_id) {
    thread_t* me = smp_current_core()->curr_thread;

    struct capability* cap = cap_lookup(me->root_cnode, cap_id, 0);
    if (!cap) {
        return ERR_INVALID_CAP;
    }

    uint16_t type = cap->type;
    uintptr_t obj = atomic_load_explicit(&cap->object_ptr, memory_order_acquire);

    sys_cap_revoke(me->root_cnode, cap_id);

    if (type == CAP_TYPE_CHANNEL) {
        destroy_channel((struct ipc_channel*)obj);
    } else if (type == CAP_TYPE_PORT_SET) {
        kmem_cache_free(port_cache, (void*)obj);
    }

    return ERR_OK;
}

static int ipc_do_transfer(thread_t* sender, thread_t* receiver) {
    receiver->ipc_state.sender_badge = sender->ipc_state.sender_badge;

    // Pure Register-to-Register Transfer
    if (!sender->ipc_state.use_memory && !receiver->ipc_state.use_memory) {
        receiver->ipc_state.msg_regs[0] = sender->ipc_state.msg_regs[0];
        receiver->ipc_state.msg_regs[1] = sender->ipc_state.msg_regs[1];
        receiver->ipc_state.msg_regs[2] = sender->ipc_state.msg_regs[2];
        receiver->ipc_state.msg_regs[3] = sender->ipc_state.msg_regs[3];

        return ERR_OK;
    }

    process_t* proc_tx = sender->owner;
    process_t* proc_rx = receiver->owner;

    struct ipc_msg_info* tx = &sender->ipc_state.msg_info;
    struct ipc_msg_info* rx = &receiver->ipc_state.msg_info;

    size_t copy_len =
        (tx->data_size_max < rx->data_size_max) ? tx->data_size_max : rx->data_size_max;
    if (copy_len > 0) {
        if (copy_between_spaces(proc_rx, rx->data_buffer, proc_tx, tx->data_buffer, copy_len) !=
            0) {
            return ERR_FAULT;
        }
    }

    rx->data_size_actual = copy_len;
    tx->data_size_actual = copy_len;

    size_t cap_copy         = (tx->caps_max < rx->caps_max) ? tx->caps_max : rx->caps_max;
    size_t transferred_caps = 0;

    for (size_t i = 0; i < cap_copy; ++i) {
        uint64_t src_cap_id;
        if (copy_between_spaces(
                proc_tx,
                &src_cap_id,
                proc_tx,
                &tx->caps_buffer[i],
                sizeof(uint64_t)
            ) != 0) {
            continue;
        }

        // Lookup sender's capability from the sender thread's cnode
        struct capability* src_cap = cap_lookup(sender->root_cnode, src_cap_id, RIGHT_GRANT);
        if (!src_cap) {
            continue;
        }

        // Allocate the received capability into the receiver thread's cnode
        uint64_t dest_cap_id;
        struct capability* dest_cap = cap_alloc(receiver->root_cnode, &dest_cap_id);
        if (!dest_cap) {
            continue;
        }

        if (cap_delegate(src_cap, dest_cap, src_cap->rights) == ERR_OK) {
            copy_between_spaces(
                proc_rx,
                &rx->caps_buffer[transferred_caps],
                proc_tx,
                &dest_cap_id,
                sizeof(uint64_t)
            );

            transferred_caps++;
        } else {
            cap_revoke(receiver->root_cnode, dest_cap);
        }
    }

    rx->caps_actual = transferred_caps;
    tx->caps_actual = transferred_caps;

    return (copy_len < tx->data_size_max || transferred_caps < tx->caps_max) ? ERR_DENIED : ERR_OK;
}

int sys_ipc_bind(uint64_t port_cap_id, uint64_t chan_cap_id, uint64_t key) {
    thread_t* me = smp_current_core()->curr_thread;

    struct capability* p_cap = cap_lookup(me->root_cnode, port_cap_id, RIGHT_WRITE);
    struct capability* c_cap = cap_lookup(me->root_cnode, chan_cap_id, RIGHT_WRITE);

    if (!p_cap || !c_cap || p_cap->type != CAP_TYPE_PORT_SET || c_cap->type != CAP_TYPE_CHANNEL) {
        return ERR_INVALID_CAP;
    }

    struct ipc_port_set* set =
        (struct ipc_port_set*)atomic_load_explicit(&p_cap->object_ptr, memory_order_acquire);
    struct ipc_channel* chan =
        (struct ipc_channel*)atomic_load_explicit(&c_cap->object_ptr, memory_order_acquire);

    acquire_qspinlock(&chan->header.lock);
    chan->wait_set = set;
    chan->user_key = key;
    release_qspinlock(&chan->header.lock);

    return ERR_OK;
}

int sys_ipc_send(uint64_t chan_cap_id, struct ipc_msg_info* user_info, struct syscall_regs* regs) {
    thread_t* me = smp_current_core()->curr_thread;

    if (!user_info) {
        me->ipc_state.use_memory = false;

        arch_sys_ipc_send(regs, &me->ipc_state);
    } else {
        me->ipc_state.use_memory = true;

        if (unlikely(
                copy_from_user(&me->ipc_state.msg_info, user_info, sizeof(struct ipc_msg_info)) != 0
            )) {
            return ERR_FAULT;
        }
    }

    struct capability* c_cap = cap_lookup(me->root_cnode, chan_cap_id, RIGHT_SEND);
    if (unlikely(!c_cap || c_cap->type != CAP_TYPE_CHANNEL)) {
        return ERR_INVALID_CAP;
    }

    me->ipc_state.sender_badge = c_cap->badge;

    struct ipc_channel* chan =
        (struct ipc_channel*)atomic_load_explicit(&c_cap->object_ptr, memory_order_acquire);
    struct ipc_channel* dest = chan->peer;
    if (unlikely(!dest || chan->peer_closed)) {
        return ERR_FAULT;
    }

    struct ipc_channel* first_lock  = (chan < dest) ? chan : dest;
    struct ipc_channel* second_lock = (chan < dest) ? dest : chan;

    acquire_qspinlock(&first_lock->header.lock);
    acquire_qspinlock(&second_lock->header.lock);

    if (unlikely(!chan->peer || chan->peer_closed)) {
        release_qspinlock(&second_lock->header.lock);
        release_qspinlock(&first_lock->header.lock);
        return ERR_FAULT;
    }

    if (!dlist_empty(&dest->blocked_receivers)) {
        struct dlist_head* first = dest->blocked_receivers.next;
        thread_t* receiver       = dlist_entry(first, thread_t, wait_node);
        dlist_del(first);

        int status = ipc_do_transfer(me, receiver);

        receiver->ipc_state.status = status;
        scheduler_unblock(receiver);

        release_qspinlock(&second_lock->header.lock);
        release_qspinlock(&first_lock->header.lock);

        if (me->ipc_state.use_memory) {
            copy_to_user(user_info, &me->ipc_state.msg_info, sizeof(struct ipc_msg_info));
        }

        return status;
    }

    dlist_add_tail(&me->wait_node, &dest->blocked_senders);
    sys_ipc_notify_internal(dest);

    scheduler_block();

    release_qspinlock(&second_lock->header.lock);
    release_qspinlock(&first_lock->header.lock);

    if (me->ipc_state.use_memory) {
        copy_to_user(user_info, &me->ipc_state.msg_info, sizeof(struct ipc_msg_info));
    }

    return me->ipc_state.status;
}

int sys_ipc_recv(uint64_t chan_cap_id, struct ipc_msg_info* user_info, struct syscall_regs* regs) {
    thread_t* me = smp_current_core()->curr_thread;

    if (user_info == nullptr) {
        me->ipc_state.use_memory = false;
    } else {
        me->ipc_state.use_memory = true;

        if (unlikely(
                copy_from_user(&me->ipc_state.msg_info, user_info, sizeof(struct ipc_msg_info)) != 0
            )) {
            return ERR_FAULT;
        }
    }

    struct capability* c_cap = cap_lookup(me->root_cnode, chan_cap_id, RIGHT_RECEIVE);
    if (unlikely(!c_cap || c_cap->type != CAP_TYPE_CHANNEL)) {
        return ERR_INVALID_CAP;
    }

    struct ipc_channel* chan =
        (struct ipc_channel*)atomic_load_explicit(&c_cap->object_ptr, memory_order_acquire);

    acquire_qspinlock(&chan->header.lock);

    if (unlikely(chan->peer_closed && dlist_empty(&chan->blocked_senders))) {
        release_qspinlock(&chan->header.lock);
        return ERR_FAULT;
    }

    if (!dlist_empty(&chan->blocked_senders)) {
        struct dlist_head* first = chan->blocked_senders.next;
        thread_t* sender         = dlist_entry(first, thread_t, wait_node);
        dlist_del(first);

        int status = ipc_do_transfer(sender, me);

        sender->ipc_state.status = status;
        scheduler_unblock(sender);

        release_qspinlock(&chan->header.lock);

        if (me->ipc_state.use_memory) {
            copy_to_user(user_info, &me->ipc_state.msg_info, sizeof(struct ipc_msg_info));
        } else {
            arch_sys_ipc_recv(regs, &me->ipc_state);
        }

        return status;
    }

    dlist_add_tail(&me->wait_node, &chan->blocked_receivers);

    scheduler_block();
    release_qspinlock(&chan->header.lock);

    if (me->ipc_state.use_memory) {
        me->ipc_state.msg_info.sender_badge = me->ipc_state.sender_badge;
        copy_to_user(user_info, &me->ipc_state.msg_info, sizeof(struct ipc_msg_info));
    } else {
        arch_sys_ipc_recv(regs, &me->ipc_state);
    }

    return me->ipc_state.status;
}

int sys_ipc_call(
    uint64_t chan_cap_id,
    struct ipc_msg_info* send_info,
    struct ipc_msg_info* recv_info,
    struct syscall_regs* regs
) {
    int ret = sys_ipc_send(chan_cap_id, send_info, regs);

    if (unlikely(ret != ERR_OK)) {
        return ret;
    }

    return sys_ipc_recv(chan_cap_id, recv_info, regs);
}

int sys_ipc_wait(uint64_t port_cap_id, struct ipc_event* out_event, int timeout_ms) {
    thread_t* me = smp_current_core()->curr_thread;

    struct capability* p_cap = cap_lookup(me->root_cnode, port_cap_id, RIGHT_WAIT);
    if (unlikely(!p_cap || p_cap->type != CAP_TYPE_PORT_SET)) {
        return ERR_INVALID_CAP;
    }

    struct ipc_port_set* set =
        (struct ipc_port_set*)atomic_load_explicit(&p_cap->object_ptr, memory_order_acquire);

    int ret = ERR_OK;
    acquire_qspinlock(&set->header.lock);

    while (dlist_empty(&set->event_queue)) {
        if (timeout_ms == 0) {
            ret = ERR_DENIED;
            break;
        }

        dlist_add_tail(&me->wait_node, &set->waiters);
        release_qspinlock(&set->header.lock);

        scheduler_sleep((uint32_t)timeout_ms);

        acquire_qspinlock(&set->header.lock);

        if (dlist_linked(&me->wait_node)) {
            dlist_del_init(&me->wait_node);
            if (dlist_empty(&set->event_queue)) {
                ret = ERR_DENIED;
                break;
            }
        }
    }

    if (ret == ERR_OK && !dlist_empty(&set->event_queue)) {
        struct dlist_head* first = set->event_queue.next;
        struct ipc_channel* chan = dlist_entry(first, struct ipc_channel, port_node);

        if (out_event) {
            struct ipc_event evt = {
                .key    = chan->user_key,
                .events = IPC_EVENT_READABLE | (chan->peer_closed ? IPC_EVENT_CLOSED : 0)
            };

            copy_to_user(out_event, &evt, sizeof(struct ipc_event));
        }

        dlist_del_init(first);
        chan->is_in_port_set = false;
    }

    release_qspinlock(&set->header.lock);
    return ret;
}