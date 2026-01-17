#include "drivers/timer.h"

#include <errno.h>

#include "libs/list.h"
#include "libs/log.h"
#include "libs/spinlock.h"

static void timer_insert_sorted(timer_manager_t* manager, timer_event_t* timer) {
    struct list_node* pos;

    list_for_each(pos, &manager->head) {
        timer_event_t* entry = container_of(pos, timer_event_t, node);

        if (entry->expires_at > timer->expires_at) {
            __list_add(&timer->node, pos->prev, pos);
            return;
        }
    }

    // If list is empty or we are the latest, add to tail
    list_push_back(&manager->head, &timer->node);
}

static void
timer_setup(timer_event_t* timer, size_t interval, timer_callback_t callback, void* ctx) {
    timer->interval = interval;
    timer->callback = callback;
    timer->ctx      = ctx;

    timer->node.next = nullptr;
    timer->node.prev = nullptr;
}

void timer_manager_init(timer_manager_t* manager) {
    if (!manager) {
        errno = EINVAL;
        KLOG_WARN("TIMER: manager_init called with null manager\n");
        return;
    }

    list_init(&manager->head);
    manager->curr_ticks = 0;
    create_spinlock(&manager->lock);

    KLOG_DEBUG("TIMER: manager initialized\n");
}

void timer_arm_oneshot(
    timer_manager_t* manager,
    timer_event_t* timer,
    uint64_t delay,
    timer_callback_t callback,
    void* ctx
) {
    if (!manager || !timer) {
        errno = EINVAL;
        KLOG_WARN(
            "TIMER: arm_oneshot called with invalid args manager=%p timer=%p\n",
            manager,
            timer
        );
        return;
    }

    acquire_spinlock(&manager->lock);

    timer_setup(timer, 0, callback, ctx);
    timer->expires_at = manager->curr_ticks + delay;
    timer->owner      = manager;
    timer_insert_sorted(manager, timer);

    release_spinlock(&manager->lock);
}

void timer_arm_periodic(
    timer_manager_t* manager,
    timer_event_t* timer,
    uint64_t interval,
    timer_callback_t callback,
    void* ctx
) {
    if (!manager || !timer) {
        errno = EINVAL;
        KLOG_WARN(
            "TIMER: arm_periodic called with invalid args manager=%p timer=%p\n",
            manager,
            timer
        );
        return;
    }

    acquire_spinlock(&manager->lock);

    timer_setup(timer, interval, callback, ctx);
    timer->expires_at = manager->curr_ticks + interval;
    timer->owner      = manager;
    timer_insert_sorted(manager, timer);

    release_spinlock(&manager->lock);
}

bool timer_cancel(timer_event_t* timer) {
    if (!timer->owner) {
        return false;
    }

    timer_manager_t* manager = timer->owner;

    acquire_spinlock(&manager->lock);

    bool removed = false;

    if (timer->node.next && timer->node.prev) {
        list_remove(&timer->node);

        timer->node.next = nullptr;
        timer->node.prev = nullptr;
        timer->owner     = nullptr;

        removed = true;
    }

    release_spinlock(&manager->lock);

    if (removed) {
        KLOG_DEBUG("TIMER: canceled timer manager=%p\n", (void*)manager);
    }

    return removed;
}

void timer_manager_tick(timer_manager_t* manager) {
    if (!manager) {
        errno = EINVAL;
        KLOG_WARN("TIMER: tick called with null manager\n");
        return;
    }

    acquire_spinlock(&manager->lock);

    manager->curr_ticks++;

    struct list_node* pos = nullptr;
    struct list_node* n   = nullptr;

    list_for_each_safe(pos, n, &manager->head) {
        timer_event_t* entry = container_of(pos, timer_event_t, node);

        if (entry->expires_at > manager->curr_ticks) {
            break;
        }

        list_remove(&entry->node);

        if (entry->callback) {
            entry->callback(entry->ctx);
        }

        if (entry->interval > 0) {
            entry->expires_at += entry->interval;
            timer_insert_sorted(manager, entry);
        } else {
            entry->owner     = nullptr;
            entry->node.next = nullptr;
            entry->node.prev = nullptr;
        }
    }

    release_spinlock(&manager->lock);
}