#include "sched/ipc.h"

#include <errno.h>
#include <stdatomic.h>
#include <stdint.h>
#include <string.h>

#include "cpu/smp.h"
#include "drivers/timer.h"
#include "libs/dlist.h"
#include "libs/handles.h"
#include "libs/math.h"
#include "libs/spinlock.h"
#include "memory/heap.h"
#include "memory/memory.h"
#include "memory/pagemap.h"
#include "memory/vma.h"
#include "sched/process.h"
#include "sched/scheduler.h"
#include "sched/syscalls.h"
#include "uapi/ipc.h"

#define TIMER_FLAG_PERIODIC (1 << 0)

struct ipc_timer {
    ipc_object_t header;

    timer_event_t hw_timer;
    ipc_port_set_t* port;
    uint64_t user_key;

    ipc_kernel_event_t event_node;
};

struct ipc_shared_mem {
    ipc_object_t header;

    size_t size;
    size_t page_count;
    uintptr_t* pages;
};

static kmem_cache_t* channel_cache = nullptr;
static kmem_cache_t* event_cache   = nullptr;
static kmem_cache_t* timer_cache   = nullptr;

static void sys_ipc_notify_internal(ipc_channel_t* dest);

static inline void thread_queue_init(struct thread_queue* tq) {
    dlist_init(&tq->list);
}

static inline bool thread_queue_empty(struct thread_queue* tq) {
    return dlist_empty(&tq->list);
}

static inline void thread_queue_push(struct thread_queue* tq, thread_t* t) {
    dlist_add_tail(&t->wait_node, &tq->list);
}

static thread_t* thread_queue_pop(struct thread_queue* tq) {
    if (dlist_empty(&tq->list)) {
        return nullptr;
    }

    struct dlist_head* first = tq->list.next;
    thread_t* t              = dlist_entry(first, thread_t, wait_node);

    dlist_del(first);
    return t;
}

static int32_t alloc_handle(process_t* proc, ipc_object_t* obj, uint32_t rights) {
    handle_t h = handle_alloc(&proc->handle_table, obj, rights);

    if (h < 0) {
        return -EMFILE;
    }

    atomic_fetch_add(&obj->ref_count, 1);
    return (int32_t)h;
}

static void* get_object(process_t* proc, int32_t handle, ipc_obj_type_t type, uint32_t rights) {
    ipc_object_t* obj = handle_lookup(&proc->handle_table, (handle_t)handle, rights);

    if (!obj) {
        return nullptr;
    }

    if ((obj->type != type) && (type != OBJ_ANY)) {
        return nullptr;
    }

    atomic_fetch_add(&obj->ref_count, 1);
    return obj;
}

static void put_object(process_t* proc, ipc_object_t* obj) {
    if (!obj) {
        return;
    }

    if (atomic_fetch_sub(&obj->ref_count, 1) == 1) {
        if (obj->type == OBJ_CHANNEL) {
            ipc_channel_t* chan = (ipc_channel_t*)obj;

            if (chan->peer) {
                acquire_spinlock(&chan->peer->header.lock);

                chan->peer->peer        = nullptr;
                chan->peer->peer_closed = true;
                sys_ipc_notify_internal(chan->peer);

                release_spinlock(&chan->peer->header.lock);
            }

            ipc_msg_t *msg, *n;
            dlist_for_each_entry_safe(msg, n, &chan->msg_queue, node) {
                dlist_del(&msg->node);

                for (size_t i = 0; i < msg->num_handles; ++i) {
                    put_object(proc, msg->handles[i]);
                }

                kfree(msg);
            }

            kmem_cache_free(channel_cache, chan);
        } else if (obj->type == OBJ_TIMER) {
            timer_cancel(&((struct ipc_timer*)obj)->hw_timer);
            kmem_cache_free(timer_cache, obj);
        } else {
            kfree(obj);
        }
    }
}

static int get_handle_rights(process_t* proc, int32_t handle, uint32_t* rights_out) {
    return handle_get_rights(&proc->handle_table, (handle_t)handle, rights_out);
}

void sys_ipc_close(int32_t handle) {
    process_t* me     = smp_current_core()->curr_thread->owner;
    ipc_object_t* obj = handle_free(&me->handle_table, (handle_t)handle);
    put_object(me, obj);
}

int sys_ipc_create_channel(int32_t* handles_out) {
    process_t* me = smp_current_core()->curr_thread->owner;

    if (!channel_cache) {
        channel_cache = kmem_cache_create(
            "ipc_channel_cache",
            sizeof(ipc_channel_t),
            sizeof(ipc_channel_t),
            0,
            nullptr
        );
    }

    ipc_channel_t* ch1 = kmem_cache_alloc(channel_cache);
    ipc_channel_t* ch2 = kmem_cache_alloc(channel_cache);

    if (!ch1 || !ch2) {
        if (ch1) {
            kmem_cache_free(channel_cache, ch1);
        }

        if (ch2) {
            kmem_cache_free(channel_cache, ch2);
        }

        return -ENOMEM;
    }

    memset(ch1, 0, sizeof(ipc_channel_t));
    memset(ch2, 0, sizeof(ipc_channel_t));

    ch1->header.type = OBJ_CHANNEL;
    create_spinlock(&ch1->header.lock);
    dlist_init(&ch1->msg_queue);
    ch1->max_msg_count = 1024;

    ch2->header.type = OBJ_CHANNEL;
    create_spinlock(&ch2->header.lock);
    dlist_init(&ch2->msg_queue);
    ch2->max_msg_count = 1024;

    ch1->peer = ch2;
    ch2->peer = ch1;

    int handle1 = alloc_handle(me, &ch1->header, IPC_RIGHTS_ALL);
    if (handle1 < 0) {
        kmem_cache_free(channel_cache, ch1);
        kmem_cache_free(channel_cache, ch2);
        return handle1;
    }

    int handle2 = alloc_handle(me, &ch2->header, IPC_RIGHTS_ALL);
    if (handle2 < 0) {
        put_object(me, &ch1->header);
        kmem_cache_free(channel_cache, ch2);
        return handle2;
    }

    if (handles_out) {
        handles_out[0] = handle1;
        handles_out[1] = handle2;
    }
    return 0;
}

int sys_ipc_create_port_set(int32_t* handle_out) {
    process_t* me       = smp_current_core()->curr_thread->owner;
    ipc_port_set_t* set = kmalloc(sizeof(ipc_port_set_t));

    if (!set) {
        return -ENOMEM;
    }

    memset(set, 0, sizeof(ipc_port_set_t));

    set->header.type = OBJ_PORT_SET;
    create_spinlock(&set->header.lock);
    dlist_init(&set->event_queue);
    thread_queue_init(&set->waiters);

    int32_t handle = alloc_handle(me, &set->header, IPC_RIGHTS_ALL);
    if (handle == 0) {
        kfree(set);
        return handle;
    }

    if (handle_out) {
        *handle_out = handle;
    }

    return 0;
}

int sys_ipc_bind(int32_t port_handle, int32_t chan_handle, uint64_t key) {
    process_t* me = smp_current_core()->curr_thread->owner;

    ipc_port_set_t* set    = get_object(me, port_handle, OBJ_PORT_SET, IPC_RIGHT_READ);
    ipc_channel_t* channel = get_object(me, chan_handle, OBJ_CHANNEL, IPC_RIGHT_WRITE);

    if (!set || !channel) {
        put_object(me, (ipc_object_t*)set);
        put_object(me, (ipc_object_t*)channel);
        return -EACCES;
    }

    acquire_spinlock(&channel->header.lock);
    channel->wait_set = set;
    channel->user_key = key;
    release_spinlock(&channel->header.lock);

    put_object(me, (ipc_object_t*)set);
    put_object(me, (ipc_object_t*)channel);
    return 0;
}

void sys_ipc_notify_internal(ipc_channel_t* dest) {
    ipc_port_set_t* set = dest->wait_set;

    if (!set) {
        return;
    }

    acquire_spinlock(&set->header.lock);

    ipc_kernel_event_t* event = kmem_cache_alloc(event_cache);
    if (!event) {
        release_spinlock(&set->header.lock);
        return;
    }

    event->data.key    = dest->user_key;
    event->data.events = IPC_EVENT_READABLE;
    event->data.handle = 0;
    event->is_embedded = false;

    dlist_add_tail(&event->node, &set->event_queue);

    if (!thread_queue_empty(&set->waiters)) {
        thread_t* t = thread_queue_pop(&set->waiters);
        scheduler_unblock(t);
    }

    release_spinlock(&set->header.lock);
}

int sys_ipc_notify(int32_t chan_handle) {
    if (!event_cache) {
        event_cache = kmem_cache_create(
            "ipc_event_cache",
            sizeof(ipc_kernel_event_t),
            sizeof(ipc_kernel_event_t),
            0,
            nullptr
        );
    }

    process_t* me = smp_current_core()->curr_thread->owner;

    ipc_channel_t* src = get_object(me, chan_handle, OBJ_CHANNEL, IPC_RIGHT_WRITE);
    if (!src) {
        return -EBADF;
    }

    ipc_channel_t* dest = src->peer;
    if (!dest || src->peer_closed) {
        put_object(me, (ipc_object_t*)src);
        return -EPIPE;
    }

    ipc_channel_t* first_lock  = (src < dest) ? src : dest;
    ipc_channel_t* second_lock = (src < dest) ? dest : src;

    acquire_spinlock(&first_lock->header.lock);
    acquire_spinlock(&second_lock->header.lock);

    if (!src->peer || src->peer_closed) {
        release_spinlock(&second_lock->header.lock);
        release_spinlock(&first_lock->header.lock);

        put_object(me, (ipc_object_t*)src);
        return -EPIPE;
    }

    sys_ipc_notify_internal(dest);

    release_spinlock(&second_lock->header.lock);
    release_spinlock(&first_lock->header.lock);

    put_object(me, (ipc_object_t*)src);
    return 0;
}

int sys_ipc_wait(int32_t port_handle, ipc_event_t* out_event, int timeout_ms) {
    process_t* me       = smp_current_core()->curr_thread->owner;
    ipc_port_set_t* set = get_object(me, port_handle, OBJ_PORT_SET, IPC_RIGHT_READ);

    if (!set) {
        return -EACCES;
    }

    int ret     = 0;
    thread_t* t = smp_current_core()->curr_thread;

    acquire_spinlock(&set->header.lock);

    while (true) {
        thread_queue_push(&set->waiters, t);
        release_spinlock(&set->header.lock);

        scheduler_sleep((uint32_t)timeout_ms);

        acquire_spinlock(&set->header.lock);

        if (!dlist_empty(&t->wait_node)) {
            dlist_del(&t->wait_node);

            if (dlist_empty(&set->event_queue)) {
                ret = -EAGAIN;
                break;
            }
        }
    }

    if (ret == 0 && !dlist_empty(&set->event_queue)) {
        struct dlist_head* first  = set->event_queue.next;
        ipc_kernel_event_t* event = dlist_entry(first, ipc_kernel_event_t, node);

        if (out_event) {
            *out_event = event->data;
        }

        dlist_del(first);

        if (!event->is_embedded) {
            kmem_cache_free(event_cache, event);
        }
    }

    release_spinlock(&set->header.lock);
    put_object(me, (ipc_object_t*)set);
    return ret;
}

int sys_ipc_send_msg(
    int32_t chan_handle,
    const void* user_data,
    size_t size,
    int32_t* user_handles,
    size_t num_handles
) {
    if (!event_cache) {
        event_cache = kmem_cache_create(
            "ipc_event_cache",
            sizeof(ipc_kernel_event_t),
            sizeof(ipc_kernel_event_t),
            0,
            nullptr
        );
    }

    if (size > (UINT16_MAX + 1) || num_handles > IPC_MAX_MSG_HANDLES) {
        return -EINVAL;
    }

    process_t* me      = smp_current_core()->curr_thread->owner;
    ipc_channel_t* src = get_object(me, chan_handle, OBJ_CHANNEL, IPC_RIGHT_WRITE);
    if (!src) {
        return -EACCES;
    }

    ipc_msg_t* msg = kmalloc(sizeof(ipc_msg_t) + size);
    if (!msg) {
        put_object(me, (ipc_object_t*)src);
        return -ENOMEM;
    }

    msg->payload_size = size;
    msg->num_handles  = num_handles;

    if (size > 0 && user_data) {
        copy_from_user(msg->payload, user_data, size);
    }

    for (size_t i = 0; i < num_handles; ++i) {
        if (get_handle_rights(me, user_handles[i], &msg->handle_rights[i]) < 0 ||
            !(msg->handle_rights[i] & IPC_RIGHT_TRANSFER)) {
            for (size_t j = 0; j < i; ++j) {
                atomic_fetch_sub(&msg->handles[i]->ref_count, 1);
            }

            kfree(msg);
            put_object(me, (ipc_object_t*)src);
            return -EACCES;
        }

        msg->handles[i] = handle_lookup(&me->handle_table, (handle_t)user_handles[i], 0);
        atomic_fetch_add(&msg->handles[i]->ref_count, 1);
    }

    ipc_channel_t* dest = src->peer;
    if (!dest || src->peer_closed) {
        for (size_t i = 0; i < num_handles; ++i) {
            atomic_fetch_sub(&msg->handles[i]->ref_count, 1);
        }

        kfree(msg);
        put_object(me, (ipc_object_t*)src);
        return -EPIPE;
    }

    ipc_channel_t* first_lock  = (src < dest) ? src : dest;
    ipc_channel_t* second_lock = (src < dest) ? dest : src;

    acquire_spinlock(&first_lock->header.lock);
    acquire_spinlock(&second_lock->header.lock);

    if (!src->peer || src->peer_closed) {
        release_spinlock(&second_lock->header.lock);
        release_spinlock(&first_lock->header.lock);

        for (size_t i = 0; i < num_handles; ++i) {
            atomic_fetch_sub(&msg->handles[i]->ref_count, 1);
        }

        kfree(msg);
        put_object(me, (ipc_object_t*)src);
        return -EPIPE;
    }

    if (dest->msg_count >= dest->max_msg_count) {
        release_spinlock(&second_lock->header.lock);
        release_spinlock(&first_lock->header.lock);

        for (size_t i = 0; i < num_handles; ++i) {
            atomic_fetch_sub(&msg->handles[i]->ref_count, 1);
        }

        kfree(msg);
        put_object(me, (ipc_object_t*)src);
        return -EAGAIN;
    }

    dlist_add_tail(&msg->node, &dest->msg_queue);
    dest->msg_count++;

    sys_ipc_notify_internal(dest);

    release_spinlock(&second_lock->header.lock);
    release_spinlock(&first_lock->header.lock);

    put_object(me, (ipc_object_t*)src);
    return 0;
}

int sys_ipc_recv_msg(int32_t chan_handle, ipc_msg_info_t* user_info) {
    if (!user_info) {
        return -EINVAL;
    }

    process_t* me = smp_current_core()->curr_thread->owner;

    ipc_msg_info_t info;
    if (copy_from_user(&info, user_info, sizeof(ipc_msg_info_t)) > 0) {
        return -EFAULT;
    }

    ipc_channel_t* channel = get_object(me, chan_handle, OBJ_CHANNEL, IPC_RIGHT_READ);
    if (!channel) {
        return -EACCES;
    }

    acquire_spinlock(&channel->header.lock);
    if (dlist_empty(&channel->msg_queue)) {
        release_spinlock(&channel->header.lock);
        put_object(me, (ipc_object_t*)channel);
        return channel->peer_closed ? -EPIPE : -EAGAIN;
    }

    struct dlist_head* first = channel->msg_queue.next;
    ipc_msg_t* msg           = dlist_entry(first, ipc_msg_t, node);

    dlist_del(first);
    channel->msg_count--;

    release_spinlock(&channel->header.lock);

    size_t copy_size =
        (msg->payload_size < info.data_size_max) ? msg->payload_size : info.data_size_max;
    if (copy_size > 0 && info.data_buffer) {
        copy_to_user(info.data_buffer, msg->payload, copy_size);
    }

    info.data_size_actual = msg->payload_size;

    size_t handle_copy =
        (msg->num_handles < info.handles_max) ? msg->num_handles : info.handles_max;

    int32_t temp_handles[IPC_MAX_MSG_HANDLES];
    for (size_t i = 0; i < handle_copy; ++i) {
        temp_handles[i] = alloc_handle(me, msg->handles[i], msg->handle_rights[i]);
        atomic_fetch_sub(&msg->handles[i]->ref_count, 1);
    }

    if (handle_copy > 0 && info.handles_buffer) {
        copy_to_user(info.handles_buffer, temp_handles, handle_copy * sizeof(int32_t));
    }

    for (size_t i = handle_copy; i < msg->num_handles; ++i) {
        put_object(me, msg->handles[i]);
    }

    info.handles_actual = msg->num_handles;

    copy_to_user(user_info, &info, sizeof(ipc_msg_info_t));

    kfree(msg);
    put_object(me, (ipc_object_t*)channel);
    return (copy_size < msg->payload_size || handle_copy < msg->num_handles) ? -E2BIG : 0;
}

static void ipc_timer_callback(void* ctx) {
    struct ipc_timer* t = (struct ipc_timer*)ctx;
    ipc_port_set_t* set = t->port;

    if (!set) {
        return;
    }

    acquire_spinlock(&set->header.lock);

    if (t->event_node.node.next == nullptr) {
        dlist_add_tail(&t->event_node.node, &set->event_queue);

        if (!dlist_empty(&set->waiters.list)) {
            thread_t* thread = thread_queue_pop(&set->waiters);
            scheduler_unblock(thread);
        }
    }

    release_spinlock(&set->header.lock);
}

int sys_ipc_timer_arm(
    int32_t port_handle,
    uint64_t user_key,
    uint64_t deadline_ms,
    int flags,
    int32_t* handle_out
) {
    if (deadline_ms == 0) {
        return -EINVAL;
    }

    process_t* me        = smp_current_core()->curr_thread->owner;
    ipc_port_set_t* set  = get_object(me, port_handle, OBJ_PORT_SET, IPC_RIGHT_WRITE);
    timer_manager_t* mgr = &smp_current_core()->timer_manager;

    if (!set) {
        return -EACCES;
    }

    if (!timer_cache) {
        timer_cache = kmem_cache_create(
            "ipc_timer_cache",
            sizeof(struct ipc_timer),
            sizeof(struct ipc_timer),
            0,
            nullptr
        );
    }

    struct ipc_timer* t = kmem_cache_alloc(timer_cache);
    if (!t) {
        put_object(me, (ipc_object_t*)set);
        return -ENOMEM;
    }

    memset(t, 0, sizeof(struct ipc_timer));

    t->header.type = OBJ_TIMER;
    create_spinlock(&t->header.lock);

    t->port                   = set;
    t->user_key               = user_key;
    t->event_node.is_embedded = true;
    t->event_node.node.next   = nullptr;

    atomic_fetch_add(&set->header.ref_count, 1);

    size_t ticks = (deadline_ms * timer_get_hz()) / 1000;
    if (ticks == 0) {
        ticks = 1;
    }

    if (flags & TIMER_FLAG_PERIODIC) {
        timer_arm(mgr, &t->hw_timer, 0, ticks, ipc_timer_callback, t);
    } else {
        timer_arm(mgr, &t->hw_timer, ticks, 0, ipc_timer_callback, t);
    }

    int32_t handle = alloc_handle(me, &t->header, IPC_RIGHTS_ALL);

    if (handle < 0) {
        timer_cancel(&t->hw_timer);
        kmem_cache_free(timer_cache, t);
        atomic_fetch_sub(&set->header.ref_count, 1);
        put_object(me, (ipc_object_t*)set);
        return handle;
    }

    *handle_out = handle;
    put_object(me, (ipc_object_t*)set);
    return 0;
}

static void ipc_shm_free(process_t* proc, struct ipc_shared_mem* shm) {
    if (!shm) {
        return;
    }

    for (size_t i = 0; i < shm->page_count; ++i) {
        if (shm->pages[i]) {
            vmfree(&proc->space, (void*)shm->pages[i], PAGE_SIZE_SMALL);
        }
    }

    kfree(shm->pages);
    kfree(shm);
}

int sys_ipc_shm_alloc(size_t size, int flags, int32_t* handle_out, uintptr_t* vaddr_out) {
    if (size == 0) {
        return -EINVAL;
    }

    process_t* me = smp_current_core()->curr_thread->owner;

    size_t aligned_size = align_up(size, PAGE_SIZE_SMALL);
    size_t page_count   = aligned_size / PAGE_SIZE_SMALL;

    struct ipc_shared_mem* shm = kmalloc(sizeof(struct ipc_shared_mem));
    if (!shm) {
        return -ENOMEM;
    }

    shm->header.type = OBJ_SHARED_MEM;
    create_spinlock(&shm->header.lock);
    shm->size       = aligned_size;
    shm->page_count = page_count;
    shm->pages      = kmalloc(sizeof(uintptr_t) * page_count);

    if (!shm->pages) {
        kfree(shm);
        return -ENOMEM;
    }

    acquire_spinlock(&shm->header.lock);

    for (size_t i = 0; i < page_count; ++i) {
        void* virt_addr = vmalloc(
            &me->space,
            nullptr,
            PAGE_SIZE_SMALL,
            (uint32_t)flags,
            CACHE_WRITE_BACK,
            PAGE_SIZE_SMALL
        );

        if (!virt_addr) {
            shm->page_count = i;
            release_spinlock(&shm->header.lock);
            ipc_shm_free(me, shm);
            return -ENOMEM;
        }

        memset(virt_addr, 0, PAGE_SIZE_SMALL);
        shm->pages[i] = (uintptr_t)virt_addr;
    }

    release_spinlock(&shm->header.lock);

    int32_t handle = alloc_handle(me, &shm->header, IPC_RIGHTS_ALL);
    if (handle == 0) {
        ipc_shm_free(me, shm);
        return handle;
    }

    acquire_spinlock(&shm->header.lock);
    *handle_out = handle;
    *vaddr_out  = shm->pages[0];
    release_spinlock(&shm->header.lock);

    return 0;
}

int sys_ipc_inspect(int32_t handle, struct ipc_info* info) {
    if (!info) {
        return -EINVAL;
    }

    process_t* me = smp_current_core()->curr_thread->owner;

    uint32_t rights = 0;
    if (get_handle_rights(me, handle, &rights) < 0) {
        return -EBADF;
    }

    ipc_object_t* obj = get_object(me, handle, OBJ_ANY, IPC_RIGHT_INSPECT);

    if (!obj) {
        return -EACCES;
    }

    memset(info, 0, sizeof(struct ipc_info));
    info->type      = obj->type;
    info->ref_count = atomic_load(&obj->ref_count);
    info->rights    = rights;

    acquire_spinlock(&obj->lock);

    switch (obj->type) {
        case OBJ_CHANNEL: {
            ipc_channel_t* chan          = (ipc_channel_t*)obj;
            info->channel.user_key       = chan->user_key;
            info->channel.queued_handles = chan->msg_count;

            if (chan->peer) {
                info->channel.peer_alive  = true;
                info->channel.peer_handle = 1;
            } else {
                info->channel.peer_alive  = false;
                info->channel.peer_handle = -1;
            }
            break;
        }

        case OBJ_PORT_SET: {
            ipc_port_set_t* set           = (ipc_port_set_t*)obj;
            info->port_set.pending_events = dlist_count(&set->event_queue);
            info->port_set.active_threads = dlist_count(&set->waiters.list);
            break;
        }

        case OBJ_SHARED_MEM: {
            struct ipc_shared_mem* shm = (struct ipc_shared_mem*)obj;
            info->shm.size_bytes       = shm->size;
            info->shm.page_count       = shm->page_count;
            break;
        }

        case OBJ_TIMER: {
            struct ipc_timer* t = (struct ipc_timer*)obj;

            info->timer.deadline = t->hw_timer.expires_at;
            break;
        }

        case OBJ_ANY:
        default:
            break;
    }

    release_spinlock(&obj->lock);
    put_object(me, obj);
    return 0;
}