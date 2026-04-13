#include "drivers/ktimer.h"

#include <stdatomic.h>
#include <stdint.h>
#include <string.h>

#include "core/capability.h"
#include "core/errors.h"
#include "core/syscalls.h"
#include "cpu/smp.h"
#include "libs/kobject.h"
#include "libs/spinlock.h"
#include "memory/heap.h"
#include "sched/ipc.h"
#include "sched/process.h"
#include "uapi/ipc.h"

#include "drivers/internal/hr_timer.h"
#include "drivers/internal/lr_timer.h"

static kmem_cache_t* timer_cache = nullptr;

void ktimer_init(void) {
    timer_cache = kmem_cache_create(
        "kernel_timer",
        sizeof(struct kernel_timer),
        _Alignof(struct kernel_timer),
        0,
        nullptr
    );
}

static void timer_fired_callback(void* ctx) {
    struct kernel_timer* timer = (struct kernel_timer*)ctx;

    size_t flags = acquire_qinterrupt_lock(&timer->lock);
    if (timer->bound_port) port_notify(timer->bound_port, &timer->port_state, IPC_SIGNAL_READABLE);
    release_qinterrupt_lock(&timer->lock, flags);
}

void ktimer_release(struct kobject* ref) {
    struct kernel_timer* timer = container_of(ref, struct kernel_timer, refcount);

    acquire_qspinlock(&timer->lock);

    if (timer->state == KTIMER_STATE_LR)
        lrtimer_cancel(&timer->event.lr);
    else
        hrtimer_cancel(&timer->event.hr);

    timer->state = KTIMER_STATE_UNARMED;
    if (timer->bound_port) kref_put(&timer->bound_port->refcount, ipc_port_release);

    release_qspinlock(&timer->lock);
    kmem_cache_free(timer_cache, timer);
}

int sys_timer_create(uint64_t* cap_out) {
    process_t* proc = smp_current_core()->curr_thread->owner;

    struct kernel_timer* timer = kmem_cache_alloc(timer_cache);
    if (!timer) return ERR_NO_MEM;

    memset(timer, 0, sizeof(struct kernel_timer));
    timer->port_state.auto_clear = IPC_EVENT_EDGE_TRIGGERED;
    kref_init(&timer->refcount, CAP_TYPE_TIMER);
    create_qspinlock(&timer->lock);

    timer->state = KTIMER_STATE_UNARMED;
    dlist_init(&timer->port_state.port_node);

    uint64_t cap;
    struct capability* c = cap_alloc(proc->root_cnode, &cap);

    if (!c) {
        kmem_cache_free(timer_cache, timer);
        return ERR_NO_MEM;
    }

    atomic_store_explicit(&c->object_ptr, (uintptr_t)timer, memory_order_release);
    c->type   = CAP_TYPE_TIMER;
    c->rights = RIGHT_ALL;

    if (cap_out) copy_to_user(cap_out, &cap, sizeof(uint64_t));
    return ERR_OK;
}

int sys_timer_set(uint64_t timer_cap, uint64_t delay_ns, uint64_t interval_ns) {
    per_cpu_data_t* cpu = smp_current_core();
    process_t* proc     = cpu->curr_thread->owner;

    struct capability* cap = cap_lookup(proc->root_cnode, timer_cap, RIGHT_WRITE | RIGHT_TIMER_ARM);
    if (!cap || cap->type != CAP_TYPE_TIMER) return ERR_INVALID_CAP;

    struct kernel_timer* timer =
        (struct kernel_timer*)atomic_load_explicit(&cap->object_ptr, memory_order_acquire);

    size_t flags = acquire_qinterrupt_lock(&timer->lock);

    // Canacquire_qspinlockcel any existing armed timer before modifying the union state
    if (timer->state == KTIMER_STATE_LR)
        lrtimer_cancel(&timer->event.lr);
    else if (timer->state == KTIMER_STATE_HR)
        hrtimer_cancel(&timer->event.hr);

    timer->port_state.pending_signals &= ~IPC_SIGNAL_READABLE;

    // Threshold Routing (any delay below 1ms is routed to hr timer)
    if (delay_ns <= HRTIMER_THRESHOLD_NS) {
        timer->state = KTIMER_STATE_HR;

        if (interval_ns > 0)
            hrtimer_arm_periodic(
                cpu->hrtimer_manager,
                &timer->event.hr,
                interval_ns,
                timer_fired_callback,
                timer
            );
        else
            hrtimer_arm_oneshot(
                cpu->hrtimer_manager,
                &timer->event.hr,
                delay_ns,
                timer_fired_callback,
                timer
            );
    } else {
        timer->state = KTIMER_STATE_LR;

        uint64_t delay_ms    = delay_ns / (NS_PER_SEC / MS_PER_SEC);
        uint64_t interval_ms = interval_ns / (NS_PER_SEC / MS_PER_SEC);

        if (interval_ms > 0)
            lrtimer_arm_periodic(
                cpu->lrtimer_manager,
                &timer->event.lr,
                interval_ms,
                timer_fired_callback,
                timer
            );
        else
            lrtimer_arm_oneshot(
                cpu->lrtimer_manager,
                &timer->event.lr,
                delay_ms,
                timer_fired_callback,
                timer
            );
    }

    release_qinterrupt_lock(&timer->lock, flags);
    return ERR_OK;
}

int sys_timer_cancel(uint64_t timer_cap) {
    process_t* proc = smp_current_core()->curr_thread->owner;

    struct capability* cap =
        cap_lookup(proc->root_cnode, timer_cap, RIGHT_WRITE | RIGHT_TIMER_CANCEL);
    if (!cap || cap->type != CAP_TYPE_TIMER) return ERR_INVALID_CAP;

    struct kernel_timer* timer =
        (struct kernel_timer*)atomic_load_explicit(&cap->object_ptr, memory_order_acquire);

    acquire_qspinlock(&timer->lock);

    if (timer->state == KTIMER_STATE_LR)
        lrtimer_cancel(&timer->event.lr);
    else
        hrtimer_cancel(&timer->event.hr);

    timer->state = KTIMER_STATE_UNARMED;
    timer->port_state.pending_signals &= ~IPC_SIGNAL_READABLE;

    release_qspinlock(&timer->lock);
    return ERR_OK;
}