#include "sched/ipc.h"

#include <stdalign.h>
#include <stdatomic.h>
#include <stdint.h>
#include <string.h>

#include "compiler.h"
#include "core/capability.h"
#include "core/errors.h"
#include "core/syscalls.h"
#include "cpu/smp.h"
#include "drivers/ktimer.h"
#include "libs/dlist.h"
#include "libs/spinlock.h"
#include "memory/heap.h"
#include "sched/process.h"
#include "sched/scheduler.h"
#include "uapi/ipc.h"

static kmem_cache_t* endpoint_cache  = nullptr;
static kmem_cache_t* port_cache      = nullptr;
static kmem_cache_t* pager_req_cache = nullptr;

static inline bool write_cap_out(uint64_t* ptr, uint64_t val) {
    if (!ptr) return true;

    if (!vmm_is_user_region((uintptr_t)ptr, sizeof(uint64_t))) return false;

    copy_to_user(ptr, &val, sizeof(uint64_t));
    return true;
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

    struct capability** kmsg_objects = (struct capability**)((uint8_t*)(kmsg + 1) + kmsg->data_len);
    struct cap_disp* kmsg_disps      = (struct cap_disp*)(kmsg_objects + kmsg->cap_count);

    if (copy_from_user(kmsg_disps, user_msg->caps, sizeof(struct cap_disp) * kmsg->cap_count) !=
        ERR_OK)
        return ERR_FAULT;

    for (size_t i = 0; i < kmsg->cap_count; i++) {
        uint64_t cid = kmsg_disps[i].cap_id;

        struct capability* src_cap = cap_lookup(proc->root_cnode, cid, kmsg_disps[i].rights);
        if (!src_cap) return ERR_INVALID_CAP;

        void* obj = (void*)atomic_load_explicit(&src_cap->object_ptr, memory_order_acquire);
        cap_object_ref(src_cap->type, obj);

        kmsg_objects[i] = src_cap;

        if (kmsg_disps[i].op == IPC_CAP_OP_MOVE) cap_close(proc->root_cnode, cid);
    }

    return ERR_OK;
}

static int
msg_install_caps(process_t* proc, struct ipc_msg_internal* kmsg, struct ipc_msg* user_msg) {
    if (kmsg->cap_count == 0) return ERR_OK;

    struct capability** kmsg_objects = (struct capability**)((uint8_t*)(kmsg + 1) + kmsg->data_len);
    struct cap_disp* kmsg_disps      = (struct cap_disp*)(kmsg_objects + kmsg->cap_count);

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
        } else {
            cap_object_unref(
                src_data->type,
                (void*)atomic_load_explicit(&src_data->object_ptr, memory_order_relaxed)
            );

            kmsg_disps[i].cap_id = 0;
        }
    }

    if (copy_to_user(user_msg->caps, kmsg_disps, sizeof(struct cap_disp) * kmsg->cap_count) !=
        ERR_OK)
        return ERR_FAULT;
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

        if (msg->cap_count > 0) {
            struct capability** kmsg_objects =
                (struct capability**)((uint8_t*)(msg + 1) + msg->data_len);

            for (size_t i = 0; i < msg->cap_count; ++i) {
                struct capability* cap = kmsg_objects[i];

                if (cap) {
                    void* obj = (void*)atomic_load_explicit(&cap->object_ptr, memory_order_acquire);
                    cap_object_unref(cap->type, obj);
                }
            }
        }

        kfree(msg);
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

int sys_endpoint_create(uint64_t* cap0_out, uint64_t* cap1_out) {
    process_t* proc = smp_current_core()->curr_thread->owner;

    struct ipc_endpoint* ep0 = kmem_cache_alloc(endpoint_cache);
    struct ipc_endpoint* ep1 = kmem_cache_alloc(endpoint_cache);

    if (!ep0 || !ep1) {
        if (ep0) kmem_cache_free(endpoint_cache, ep0);
        if (ep1) kmem_cache_free(endpoint_cache, ep1);
        return ERR_NO_MEM;
    }

    memset(ep0, 0, sizeof(struct ipc_endpoint));
    memset(ep1, 0, sizeof(struct ipc_endpoint));

    kref_init(&ep0->refcount, CAP_TYPE_ENDPOINT);
    create_qspinlock(&ep0->lock);
    dlist_init(&ep0->msg_queue);
    dlist_init(&ep0->blocked_receivers);

    kref_init(&ep1->refcount, CAP_TYPE_ENDPOINT);
    create_qspinlock(&ep1->lock);
    dlist_init(&ep1->msg_queue);
    dlist_init(&ep1->blocked_receivers);

    ep0->port_state.auto_clear = IPC_EVENT_LEVEL_TRIGGERED;
    ep1->port_state.auto_clear = IPC_EVENT_LEVEL_TRIGGERED;

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
        return ERR_NO_MEM;
    }

    atomic_store_explicit(&c0->object_ptr, (uintptr_t)ep0, memory_order_release);
    c0->type   = CAP_TYPE_ENDPOINT;
    c0->rights = RIGHT_ALL;

    atomic_store_explicit(&c1->object_ptr, (uintptr_t)ep1, memory_order_release);
    c1->type   = CAP_TYPE_ENDPOINT;
    c1->rights = RIGHT_ALL;

    if (cap0_out && cap1_out)
        if (!write_cap_out(cap0_out, cap0) || !write_cap_out(cap1_out, cap1)) return ERR_FAULT;

    return ERR_OK;
}

int sys_port_create(uint64_t* cap_out) {
    process_t* proc = smp_current_core()->curr_thread->owner;

    struct ipc_port* port = kmem_cache_alloc(port_cache);
    if (!port) return ERR_NO_MEM;

    memset(port, 0, sizeof(struct ipc_port));
    kref_init(&port->refcount, CAP_TYPE_PORT);
    create_qspinlock(&port->lock);
    dlist_init(&port->event_queue);
    dlist_init(&port->waiters);

    uint64_t cap;
    struct capability* c = cap_alloc(proc->root_cnode, &cap);
    if (!c) {
        kmem_cache_free(port_cache, port);
        return ERR_NO_MEM;
    }

    atomic_store_explicit(&c->object_ptr, (uintptr_t)port, memory_order_release);
    c->type   = CAP_TYPE_PORT;
    c->rights = RIGHT_ALL;

    if (cap_out)
        if (!write_cap_out(cap_out, cap)) return ERR_FAULT;
    return ERR_OK;
}

int sys_port_bind(uint64_t port_cap, uint64_t target_cap, uint64_t key) {
    process_t* proc = smp_current_core()->curr_thread->owner;

    struct capability* p_cap = cap_lookup(proc->root_cnode, port_cap, RIGHT_WRITE);
    struct capability* t_cap = cap_lookup(proc->root_cnode, target_cap, RIGHT_WRITE);

    if (!p_cap || !t_cap || p_cap->type != CAP_TYPE_PORT) return ERR_INVALID_CAP;

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

    return ERR_INVALID_CAP;
}

int sys_channel_write(uint64_t ep_cap_id, struct ipc_msg* user_msg) {
    process_t* proc = smp_current_core()->curr_thread->owner;

    struct capability* cap = cap_lookup(proc->root_cnode, ep_cap_id, RIGHT_WRITE);
    if (!cap) return ERR_INVALID_CAP;

    struct ipc_msg msg;
    if (copy_from_user(&msg, user_msg, sizeof(struct ipc_msg)) != 0) return ERR_FAULT;

    if (cap->type == CAP_TYPE_REPLY) {
        thread_t* target_thread =
            (thread_t*)atomic_load_explicit(&cap->object_ptr, memory_order_acquire);

        size_t total_size             = sizeof(struct ipc_msg_internal) + msg.data_len +
                                        (msg.cap_count * sizeof(struct capability*)) +
                                        (msg.cap_count * sizeof(struct cap_disp));
        struct ipc_msg_internal* kmsg = kmalloc(total_size);
        if (!kmsg) return ERR_NO_MEM;

        kmsg->data_len  = msg.data_len;
        kmsg->cap_count = msg.cap_count;
        if (msg.data_len > 0) copy_from_user((void*)(kmsg + 1), msg.data, msg.data_len);

        int err = msg_extract_caps(proc, &msg, kmsg);
        if (err != ERR_OK) {
            kfree(kmsg);
            return err;
        }

        target_thread->ipc_state.rpc_reply_msg = kmsg;
        target_thread->ipc_state.status        = ERR_OK;
        scheduler_unblock(target_thread);

        cap_close(proc->root_cnode, ep_cap_id);
        return ERR_OK;
    }

    size_t total_data_bytes = 0;
    struct ipc_iovec iovs[16];

    if (msg.flags & IPC_FLAG_IOVEC) {
        if (msg.data_len > 16) return ERR_INVALID;
        if (copy_from_user(iovs, msg.data, msg.data_len * sizeof(struct ipc_iovec)) != 0)
            return ERR_FAULT;

        for (size_t i = 0; i < msg.data_len; ++i) total_data_bytes += iovs[i].len;
    } else {
        total_data_bytes = msg.data_len;
    }

    if (unlikely(cap->type != CAP_TYPE_ENDPOINT)) return ERR_INVALID_CAP;

    size_t total_size = sizeof(struct ipc_msg_internal) + msg.data_len +
                        (msg.cap_count * sizeof(struct capability*)) +
                        (msg.cap_count * sizeof(struct cap_disp));

    struct ipc_msg_internal* kmsg = kmalloc(total_size);
    if (!kmsg) return ERR_NO_MEM;

    kmsg->data_len     = msg.data_len;
    kmsg->cap_count    = msg.cap_count;
    kmsg->sender_badge = cap->badge;

    uint8_t* kmsg_data = (uint8_t*)(kmsg + 1);
    if (msg.flags & IPC_FLAG_IOVEC) {
        size_t offset = 0;
        for (size_t i = 0; i < msg.data_len; ++i) {
            if (iovs[i].len > 0) {
                if (copy_from_user(kmsg_data + offset, iovs[i].base, iovs[i].len) != 0) {
                    kfree(kmsg);
                    return ERR_FAULT;
                }

                offset += iovs[i].len;
            }
        }
    } else if (msg.data_len > 0) {
        if (copy_from_user(kmsg_data, msg.data, msg.data_len) != 0) {
            kfree(kmsg);
            return ERR_FAULT;
        }
    }

    int err = msg_extract_caps(proc, &msg, kmsg);
    if (err != ERR_OK) {
        kfree(kmsg);
        return err;
    }

    struct ipc_endpoint* ep =
        (struct ipc_endpoint*)atomic_load_explicit(&cap->object_ptr, memory_order_acquire);

    acquire_qspinlock(&ep->lock);
    struct ipc_endpoint* peer = ep->peer;

    if (unlikely(!peer || ep->peer_closed)) {
        release_qspinlock(&ep->lock);
        kfree(kmsg);
        return ERR_IPC_DISCONNECT;
    }

    acquire_qspinlock(&peer->lock);

    if (msg.flags & IPC_FLAG_URGENT)
        dlist_add(&kmsg->node, &peer->msg_queue);
    else
        dlist_add_tail(&kmsg->node, &peer->msg_queue);

    port_notify(peer->bound_port, &peer->port_state, IPC_SIGNAL_READABLE);

    if (!dlist_empty(&peer->blocked_receivers)) {
        thread_t* t = dlist_entry(peer->blocked_receivers.next, thread_t, wait_node);
        dlist_del(&t->wait_node);
        t->ipc_state.status = ERR_OK;
        scheduler_unblock(t);
    }

    release_qspinlock(&peer->lock);
    release_qspinlock(&ep->lock);

    return ERR_OK;
}

int sys_channel_read(
    uint64_t ep_cap_id,
    struct ipc_msg* user_msg,
    uint32_t* badge_out,
    int timeout_ms
) {
    thread_t* me    = smp_current_core()->curr_thread;
    process_t* proc = me->owner;

    struct capability* cap = cap_lookup(proc->root_cnode, ep_cap_id, RIGHT_READ);
    if (unlikely(!cap || cap->type != CAP_TYPE_ENDPOINT)) return ERR_INVALID_CAP;

    struct ipc_msg msg;
    if (copy_from_user(&msg, user_msg, sizeof(struct ipc_msg)) != ERR_OK) return ERR_FAULT;

    struct ipc_endpoint* ep =
        (struct ipc_endpoint*)atomic_load_explicit(&cap->object_ptr, memory_order_acquire);

    acquire_qspinlock(&ep->lock);

    while (dlist_empty(&ep->msg_queue)) {
        if (ep->peer_closed) {
            release_qspinlock(&ep->lock);
            return ERR_IPC_DISCONNECT;
        }

        if (timeout_ms == 0) {
            release_qspinlock(&ep->lock);
            return ERR_AGAIN;
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
            return ERR_TIMEOUT;
        }

        if (me->ipc_state.status == ERR_IPC_DISCONNECT && dlist_empty(&ep->msg_queue)) {
            release_qspinlock(&ep->lock);
            return ERR_IPC_DISCONNECT;
        }
    }

    struct ipc_msg_internal* kmsg = dlist_entry(ep->msg_queue.next, struct ipc_msg_internal, node);

    if (msg.flags & IPC_FLAG_PEEK) {
        release_qspinlock(&ep->lock);

        msg.data_len  = kmsg->data_len;
        msg.cap_count = kmsg->cap_count;
        copy_to_user(user_msg, &msg, sizeof(struct ipc_msg));

        return ERR_OK;
    }

    if (msg.data_len < kmsg->data_len || msg.cap_count < kmsg->cap_count) {
        release_qspinlock(&ep->lock);

        msg.data_len  = kmsg->data_len;
        msg.cap_count = kmsg->cap_count;
        copy_to_user(user_msg, &msg, sizeof(struct ipc_msg));

        return ERR_IPC_TRUNCATED;
    }

    dlist_del_init(&kmsg->node);
    if (dlist_empty(&ep->msg_queue)) {
        ep->port_state.pending_signals &= ~IPC_SIGNAL_READABLE;
        ep->port_state.signal_count = 0;
    }

    release_qspinlock(&ep->lock);

    void* kmsg_data = (void*)(kmsg + 1);
    if (kmsg->data_len > 0) copy_to_user(msg.data, kmsg_data, kmsg->data_len);

    msg_install_caps(proc, kmsg, &msg);

    if (badge_out) copy_to_user(badge_out, &kmsg->sender_badge, sizeof(uint32_t));

    msg.data_len  = kmsg->data_len;
    msg.cap_count = kmsg->cap_count;
    copy_to_user(user_msg, &msg, sizeof(struct ipc_msg));

    kfree(kmsg);
    return ERR_OK;
}

int sys_channel_call(uint64_t ep_cap_id, struct ipc_msg* tx, struct ipc_msg* rx, int timeout_ms) {
    thread_t* me    = smp_current_core()->curr_thread;
    process_t* proc = me->owner;

    uint64_t reply_cap_id;
    struct capability* reply_cap = cap_alloc(proc->root_cnode, &reply_cap_id);
    if (!reply_cap) return ERR_NO_MEM;

    atomic_store_explicit(&reply_cap->object_ptr, (uintptr_t)me, memory_order_release);
    reply_cap->type   = CAP_TYPE_REPLY;
    reply_cap->rights = RIGHT_WRITE;

    int ret = sys_channel_write(ep_cap_id, tx);
    if (ret != ERR_OK) {
        cap_close(proc->root_cnode, reply_cap_id);
        return ret;
    }

    me->ipc_state.rpc_reply_msg = nullptr;

    if (timeout_ms > 0)
        scheduler_sleep(timeout_ms);
    else
        scheduler_block();

    cap_close(proc->root_cnode, reply_cap_id);

    if (me->ipc_state.rpc_reply_msg == nullptr) return ERR_TIMEOUT;

    struct ipc_msg_internal* kmsg = me->ipc_state.rpc_reply_msg;
    struct ipc_msg msg;
    if (copy_from_user(&msg, rx, sizeof(struct ipc_msg)) != 0) {
        kfree(kmsg);
        return ERR_FAULT;
    }

    if (msg.data_len < kmsg->data_len || msg.cap_count < kmsg->cap_count) {
        kfree(kmsg);
        return ERR_IPC_TRUNCATED;
    }

    if (kmsg->data_len > 0) copy_to_user(msg.data, (void*)(kmsg + 1), kmsg->data_len);
    msg_install_caps(proc, kmsg, &msg);

    msg.data_len  = kmsg->data_len;
    msg.cap_count = kmsg->cap_count;
    copy_to_user(rx, &msg, sizeof(struct ipc_msg));

    kfree(kmsg);
    return ERR_OK;
}

int sys_port_wait(
    uint64_t port_cap,
    struct port_event* out_events,
    size_t max_events,
    size_t* events_returned,
    int timeout_ms
) {
    thread_t* me    = smp_current_core()->curr_thread;
    process_t* proc = me->owner;

    struct capability* p_cap = cap_lookup(proc->root_cnode, port_cap, RIGHT_WAIT);
    if (unlikely(!p_cap || p_cap->type != CAP_TYPE_PORT)) return ERR_INVALID_CAP;

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

                copy_to_user(&out_events[count], &evt, sizeof(struct port_event));
            }

            count++;
        }
    }

    release_qspinlock(&set->lock);

    if (events_returned) copy_to_user(events_returned, &count, sizeof(size_t));
    return ret;
}

int sys_channel_forward(uint64_t src_ep_cap, uint64_t dest_ep_cap) {
    process_t* proc = smp_current_core()->curr_thread->owner;

    struct capability* cap_src = cap_lookup(proc->root_cnode, src_ep_cap, RIGHT_READ);
    struct capability* cap_dst = cap_lookup(proc->root_cnode, dest_ep_cap, RIGHT_WRITE);

    if (!cap_src || !cap_dst) return ERR_INVALID_CAP;
    if (cap_src->type != CAP_TYPE_ENDPOINT || cap_dst->type != CAP_TYPE_ENDPOINT)
        return ERR_INVALID_CAP;

    struct ipc_endpoint* ep_src =
        (struct ipc_endpoint*)atomic_load_explicit(&cap_src->object_ptr, memory_order_acquire);
    struct ipc_endpoint* ep_dst =
        (struct ipc_endpoint*)atomic_load_explicit(&cap_dst->object_ptr, memory_order_acquire);

    acquire_qspinlock(&ep_src->lock);
    if (dlist_empty(&ep_src->msg_queue)) {
        release_qspinlock(&ep_src->lock);
        return ERR_AGAIN;
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
        kfree(kmsg);
        return ERR_IPC_DISCONNECT;
    }

    acquire_qspinlock(&peer->lock);

    dlist_add_tail(&kmsg->node, &peer->msg_queue);
    port_notify(peer->bound_port, &peer->port_state, IPC_SIGNAL_READABLE);

    if (!dlist_empty(&peer->blocked_receivers)) {
        thread_t* t = dlist_entry(peer->blocked_receivers.next, thread_t, wait_node);
        dlist_del(&t->wait_node);
        t->ipc_state.status = ERR_OK;
        scheduler_unblock(t);
    }

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