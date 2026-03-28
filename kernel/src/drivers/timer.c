#include "drivers/timer.h"

#include <stdint.h>

#include "libs/hashtable.h"
#include "libs/log.h"
#include "libs/spinlock.h"

#define time_before_eq(a, b) ((a) <= (b))

void timer_manager_init(timer_manager_t* manager) {
    if (!manager) {
        return;
    }

    KLOG_INIT_START("Timer Manager");

    ht_init_table(manager->tv1, TVR_SIZE);
    ht_init_table(manager->tv2, TVN_SIZE);
    ht_init_table(manager->tv3, TVN_SIZE);
    ht_init_table(manager->tv4, TVN_SIZE);
    ht_init_table(manager->tv5, TVN_SIZE);

    manager->curr_ticks      = timer_get_time_ms();
    manager->next_expires_at = manager->curr_ticks;
    manager->active_timers   = 0;

    create_qspinlock(&manager->lock);
    KLOG_INIT_OK();
}

static void internal_add_timer(timer_manager_t* manager, timer_event_t* timer) {
    uint32_t expires = timer->expires_at;
    uint32_t idx     = expires - manager->curr_ticks;

    if (idx < TVR_SIZE) {
        __ht_link_node(&manager->tv1[expires & TVR_MASK], &timer->node);
        return;
    }

    struct hlist_head* wheels[] = {manager->tv2, manager->tv3, manager->tv4, manager->tv5};
    for (int i = 0; i < 4; i++) {
        if (i == 3 || idx < (1 << (TVR_BITS + (i + 1) * TVN_BITS))) {
            int shift = TVR_BITS + (i * TVN_BITS);

            __ht_link_node(&wheels[i][(expires >> shift) & TVN_MASK], &timer->node);
            return;
        }
    }
}

static void __timer_arm(
    timer_manager_t* manager,
    timer_event_t* timer,
    int64_t delay_ms,
    int64_t interval_ms,
    timer_callback_t callback,
    void* ctx
) {
    if (!manager || !timer) {
        return;
    }

    acquire_qspinlock(&manager->lock);

    ht_init_node(&timer->node);
    timer->callback   = callback;
    timer->ctx        = ctx;
    timer->interval   = interval_ms;
    timer->owner      = manager;
    timer->expires_at = manager->curr_ticks + (uint64_t)delay_ms;

    if (manager->active_timers == 0 ||
        time_before_eq(timer->expires_at, manager->next_expires_at)) {
        manager->next_expires_at = timer->expires_at;
    }

    internal_add_timer(manager, timer);
    manager->active_timers++;

    release_qspinlock(&manager->lock);
}

void timer_arm_oneshot(
    timer_manager_t* manager,
    timer_event_t* timer,
    int64_t delay_ms,
    timer_callback_t callback,
    void* ctx
) {
    __timer_arm(manager, timer, delay_ms, 0, callback, ctx);
}

void timer_arm_periodic(
    timer_manager_t* manager,
    timer_event_t* timer,
    int64_t interval_ms,
    timer_callback_t callback,
    void* ctx
) {
    __timer_arm(manager, timer, 0, interval_ms, callback, ctx);
}

bool timer_cancel(timer_event_t* timer) {
    if (!timer || !timer->owner) {
        return false;
    }

    timer_manager_t* manager = timer->owner;
    acquire_qspinlock(&manager->lock);

    if (timer->owner != manager) {
        release_qspinlock(&manager->lock);
        return false;
    }

    ht_remove(&timer->node);
    timer->owner = nullptr;
    manager->active_timers--;

    bool ret = false;
    if (timer->expires_at < timer_get_time_ms()) {
        ret = true;
    }

    release_qspinlock(&manager->lock);
    return ret;
}

static void cascade(timer_manager_t* manager, struct hlist_head* tv, int index) {
    struct hlist_head* head = &tv[index];
    struct hlist_node* n;
    timer_event_t* timer;

    struct hlist_head list = {head->first};
    if (head->first) {
        head->first->pprev = &list.first;
    }

    head->first = nullptr;

    ht_for_each_entry_safe(timer, n, &list, node) {
        ht_remove(&timer->node);
        internal_add_timer(manager, timer);
    }
}

void timer_manager_tick(timer_manager_t* manager) {
    if (!manager) {
        return;
    }

    uint32_t now = timer_get_time_ms();

    if (manager->active_timers == 0 || time_before_eq(now, manager->next_expires_at)) {
        return;
    }

    acquire_qspinlock(&manager->lock);

    while (time_before_eq(manager->curr_ticks, now)) {
        uint32_t current_idx = manager->curr_ticks & TVR_MASK;

        if (!current_idx && manager->curr_ticks != 0) {
            struct hlist_head* wheels[] = {manager->tv2, manager->tv3, manager->tv4, manager->tv5};

            for (int i = 0; i < 4; i++) {
                int shift = TVR_BITS + (i * TVN_BITS);
                int idx   = (int)((manager->curr_ticks >> shift) & TVN_MASK);

                cascade(manager, wheels[i], idx);

                // The wheel didn't wrap around, so we don't need to cascade the next level up.
                if (idx != 0) {
                    break;
                }
            }
        }

        struct hlist_head work_list = {manager->tv1[current_idx].first};
        if (manager->tv1[current_idx].first) {
            manager->tv1[current_idx].first->pprev = &work_list.first;
        }

        manager->tv1[current_idx].first = nullptr;

        release_qspinlock(&manager->lock);

        struct hlist_node* n;
        timer_event_t* timer;

        ht_for_each_entry_safe(timer, n, &work_list, node) {
            ht_remove(&timer->node);

            if (timer->callback) {
                timer->callback(timer->ctx);
            }

            acquire_qspinlock(&manager->lock);
            if (timer->interval > 0 && timer->owner == manager) {
                timer->expires_at = manager->curr_ticks + (uint64_t)timer->interval;
                internal_add_timer(manager, timer);

                if (time_before_eq(timer->expires_at, manager->next_expires_at)) {
                    manager->next_expires_at = timer->expires_at;
                }
            } else {
                timer->owner = nullptr;
                manager->active_timers--;
            }

            release_qspinlock(&manager->lock);
        }

        acquire_qspinlock(&manager->lock);
        manager->curr_ticks++;
    }

    manager->next_expires_at = manager->curr_ticks;
    release_qspinlock(&manager->lock);
}