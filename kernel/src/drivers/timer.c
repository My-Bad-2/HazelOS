#include "drivers/timer.h"

#include <errno.h>

#include "libs/log.h"
#include "libs/rb_tree.h"
#include "libs/spinlock.h"

static bool timer_insert(timer_manager_t* manager, timer_event_t* timer) {
    struct rb_node** link  = &manager->root.rb_root.rb_node;
    struct rb_node* parent = nullptr;
    bool leftmost          = true;

    while (*link) {
        parent               = *link;
        timer_event_t* entry = rb_entry(parent, timer_event_t, node);

        if (timer->expires_at < entry->expires_at) {
            link = &parent->rb_left;
        } else {
            link     = &parent->rb_right;
            leftmost = false;
        }
    }

    rb_link_node(&timer->node, parent, link);
    rb_insert_color_cached(&timer->node, &manager->root, leftmost);

    return leftmost;
}

static void
timer_setup(timer_event_t* timer, size_t interval, timer_callback_t callback, void* ctx) {
    timer->interval = interval;
    timer->callback = callback;
    timer->ctx      = ctx;

    RB_CLEAR_NODE(&timer->node);
}

void timer_manager_init(timer_manager_t* manager) {
    if (!manager) {
        errno = EINVAL;
        KLOG_WARN("TIMER: manager_init called with null manager\n");
        return;
    }

    manager->root       = RB_ROOT_CACHED;
    manager->curr_ticks = 0;
    create_spinlock(&manager->lock);

    KLOG_DEBUG("TIMER: manager initialized\n");
}

void timer_arm_oneshot(
    timer_manager_t* manager,
    timer_event_t* timer,
    uint64_t delay_ns,
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
    timer->expires_at = manager->curr_ticks + delay_ns;
    timer->owner      = manager;
    timer_insert(manager, timer);

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
    timer_insert(manager, timer);

    release_spinlock(&manager->lock);
}

bool timer_cancel(timer_event_t* timer) {
    timer_manager_t* manager = timer->owner;

    if (!manager) {
        return false;
    }

    acquire_spinlock(&manager->lock);

    if (timer->owner != manager) {
        release_spinlock(&manager->lock);
        return false;
    }

    if (!RB_EMPTY_NODE(&timer->node)) {
        rb_erase_cached(&timer->node, &manager->root);
        RB_CLEAR_NODE(&timer->node);
    }

    timer->owner = nullptr;

    release_spinlock(&manager->lock);
    return true;
}

void timer_manager_tick(timer_manager_t* manager) {
    if (!manager) {
        errno = EINVAL;
        KLOG_WARN("TIMER: tick called with null manager\n");
        return;
    }

    acquire_spinlock(&manager->lock);
    size_t now = timer_get_time() / 1000000ul;

    while (true) {
        struct rb_node* node = rb_first_cached(&manager->root);

        if (!node) {
            break;
        }

        timer_event_t* entry = rb_entry(node, timer_event_t, node);

        if (entry->expires_at > now) {
            break;
        }

        rb_erase_cached(node, &manager->root);
        RB_CLEAR_NODE(node);

        if (entry->callback) {
            entry->callback(entry->ctx);
        }

        if (entry->interval > 0) {
            entry->expires_at += entry->interval;

            timer_insert(manager, entry);
        } else {
            entry->owner = nullptr;
        }
    }

    release_spinlock(&manager->lock);
}