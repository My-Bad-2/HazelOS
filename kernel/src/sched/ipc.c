#include "sched/ipc.h"

#include <errno.h>
#include <stdint.h>
#include <string.h>

#include "cpu/smp.h"
#include "libs/dlist.h"
#include "libs/handles.h"
#include "libs/spinlock.h"
#include "memory/heap.h"
#include "memory/memory.h"
#include "memory/pagemap.h"
#include "memory/vma.h"
#include "sched/process.h"
#include "sched/scheduler.h"
#include "uapi/ipc.h"

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

static int32_t alloc_handle(process_t* proc, ipc_object_t* obj) {
    handle_t h = handle_alloc(&proc->handle_table, obj);

    if (h == 0) {
        return -EMFILE;
    }

    atomic_fetch_add(&obj->ref_count, 1);
    return (int32_t)h;
}

static void* get_object(process_t* proc, int32_t handle, ipc_obj_type_t type) {
    ipc_object_t* obj = handle_lookup(&proc->handle_table, (handle_t)handle);

    if (!obj) {
        return nullptr;
    }

    if (obj->type != type) {
        return nullptr;
    }

    return obj;
}

void sys_ipc_close(int32_t handle) {
    process_t* me = smp_current_core()->curr_thread->owner;

    ipc_object_t* obj = handle_free(&me->handle_table, (handle_t)handle);

    if (obj) {
        if (atomic_fetch_sub(&obj->ref_count, 1) == 1) {
            kfree(obj, sizeof(ipc_object_t));
        }
    }
}

int sys_ipc_create_channel(int32_t* handles_out, uintptr_t* ring_vaddr_out) {
    process_t* me = smp_current_core()->curr_thread->owner;

    ipc_channel_t* ch1 = kmalloc(sizeof(ipc_channel_t));
    ipc_channel_t* ch2 = kmalloc(sizeof(ipc_channel_t));

    if (!ch1 || !ch2) {
        return -ENOMEM;
    }

    memset(ch1, 0, sizeof(ipc_channel_t));
    memset(ch2, 0, sizeof(ipc_channel_t));

    ch1->header.type = OBJ_CHANNEL;
    create_spinlock(&ch1->header.lock);

    ch2->header.type = OBJ_CHANNEL;
    create_spinlock(&ch2->header.lock);

    // Peer linking
    ch1->peer = ch2;
    ch2->peer = ch1;

    void* kpage = vmm_alloc(
        &me->space,
        PAGE_SIZE_SMALL,
        VMM_FLAG_READ | VMM_FLAG_WRITE | VMM_FLAG_USER,
        CACHE_WRITE_BACK,
        PAGE_SIZE_SMALL
    );

    *ring_vaddr_out = (uintptr_t)kpage;

    int handle1 = alloc_handle(me, &ch1->header);
    int handle2 = alloc_handle(me, &ch2->header);

    handles_out[0] = handle1;
    handles_out[1] = handle2;

    return handle1;
}

int sys_ipc_create_port_set(int32_t* handle_out) {
    process_t* me = smp_current_core()->curr_thread->owner;

    ipc_port_set_t* set = kmalloc(sizeof(ipc_port_set_t));
    memset(set, 0, sizeof(ipc_port_set_t));

    create_spinlock(&set->header.lock);

    dlist_init(&set->event_queue);
    thread_queue_init(&set->waiters);

    int32_t handle = alloc_handle(me, &set->header);

    if (handle == 0) {
        kfree(set, sizeof(ipc_object_t));
        return handle;
    }

    *handle_out = handle;
    return 0;
}

int sys_ipc_bind(int32_t port_handle, int32_t chan_handle, uint64_t key) {
    process_t* me = smp_current_core()->curr_thread->owner;

    ipc_port_set_t* set    = get_object(me, port_handle, OBJ_PORT_SET);
    ipc_channel_t* channel = get_object(me, chan_handle, OBJ_CHANNEL);

    if (!set || !channel) {
        return -EBADF;
    }

    acquire_spinlock(&channel->header.lock);

    channel->wait_set = set;
    channel->user_key = key;

    release_spinlock(&channel->header.lock);
    return 0;
}

int sys_ipc_notify(int32_t chan_handle) {
    process_t* me      = smp_current_core()->curr_thread->owner;
    ipc_channel_t* src = get_object(me, chan_handle, OBJ_CHANNEL);

    if (!src) {
        return -EBADF;
    }

    acquire_spinlock(&src->header.lock);

    ipc_channel_t* dest = src->peer;

    if (!dest) {
        release_spinlock(&src->header.lock);
        return -EPIPE;
    }

    acquire_spinlock(&dest->header.lock);
    ipc_port_set_t* set = dest->wait_set;

    if (set) {
        acquire_spinlock(&set->header.lock);

        ipc_kernel_event_t* event = kmalloc(sizeof(ipc_kernel_event_t));
        event->data.key           = dest->user_key;
        event->data.events        = IPC_EVENT_READABLE;
        event->data.handle        = 0;  // Unknown to sender

        dlist_add_tail(&event->node, &set->event_queue);

        if (!dlist_empty(&set->waiters.list)) {
            thread_t* t = thread_queue_pop(&set->waiters);
            scheduler_unblock(t);
        }

        release_spinlock(&set->header.lock);
    }

    release_spinlock(&dest->header.lock);
    release_spinlock(&src->header.lock);

    return 0;
}

int sys_ipc_wait(int32_t port_handle, ipc_event_t* out_event, int timeout_ms) {
    process_t* me       = smp_current_core()->curr_thread->owner;
    ipc_port_set_t* set = get_object(me, port_handle, OBJ_PORT_SET);

    if (!set) {
        return -EBADF;
    }

    while (true) {
        acquire_spinlock(&set->header.lock);

        if (!dlist_empty(&set->event_queue)) {
            struct dlist_head* first  = set->event_queue.next;
            ipc_kernel_event_t* event = dlist_entry(first, ipc_kernel_event_t, node);

            dlist_del(first);
            *out_event = event->data;
            kfree(event, sizeof(ipc_kernel_event_t));

            release_spinlock(&set->header.lock);
            return 0;
        }

        thread_t* t = smp_current_core()->curr_thread;
        thread_queue_push(&set->waiters, t);

        release_spinlock(&set->header.lock);
        scheduler_sleep((uint32_t)timeout_ms);
    }
}