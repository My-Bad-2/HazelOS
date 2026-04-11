#include "drivers/ktimer.h"

#include <stdint.h>

#include "drivers/timer.h"
#include "libs/hashtable.h"
#include "libs/spinlock.h"

void timer_manager_init(timer_manager_t* manager) {
    if (!manager) return;

    ht_init_table(manager->tv1, TVR_SIZE);
    ht_init_table(manager->tv2, TVN_SIZE);
    ht_init_table(manager->tv3, TVN_SIZE);
    ht_init_table(manager->tv4, TVN_SIZE);
    ht_init_table(manager->tv5, TVN_SIZE);

    uint64_t ms = timer_get_time_ms();

    manager->curr_time_ms    = ms;
    manager->next_expires_at = ms;
    manager->active_timers   = 0;

    create_qspinlock(&manager->lock);
}

static void internal_add_timer(timer_manager_t* manager, timer_event_t* timer) {
    uint64_t expires = timer->expires_at;
    uint64_t idx     = expires - manager->curr_time_ms;

    if (idx < TVR_SIZE) {
        __ht_link_node(&manager->tv1[(uint64_t)expires & TVR_MASK], &timer->node);
        return;
    }

    struct hlist_head* wheels[] = {manager->tv2, manager->tv3, manager->tv4, manager->tv5};
    for (int i = 0; i < 4; i++) {
        if (i == 3 || idx < (1ul << (TVR_BITS + (i + 1) * TVN_BITS))) {
            int shift = TVR_BITS + (i * TVN_BITS);

            __ht_link_node(&wheels[i][((uint64_t)expires >> shift) & TVN_MASK], &timer->node);
            return;
        }
    }
}

static void __timer_arm(
    timer_manager_t* manager,
    timer_event_t* timer,
    uint64_t delay_ms,
    uint64_t interval_ms,
    timer_callback_t callback,
    void* ctx
) {
    if (!manager || !timer) return;

    acquire_qspinlock(&manager->lock);

    ht_init_node(&timer->node);
    timer->callback   = callback;
    timer->ctx        = ctx;
    timer->interval   = interval_ms;
    timer->owner      = manager;
    timer->expires_at = manager->curr_time_ms + delay_ms;

    if (manager->active_timers == 0 || timer->expires_at < manager->next_expires_at)
        manager->next_expires_at = timer->expires_at;

    internal_add_timer(manager, timer);
    manager->active_timers++;

    release_qspinlock(&manager->lock);
}

void timer_arm_oneshot(
    timer_manager_t* manager,
    timer_event_t* timer,
    uint64_t delay_ms,
    timer_callback_t callback,
    void* ctx
) {
    __timer_arm(manager, timer, delay_ms, 0, callback, ctx);
}

void timer_arm_periodic(
    timer_manager_t* manager,
    timer_event_t* timer,
    uint64_t interval_ms,
    timer_callback_t callback,
    void* ctx
) {
    __timer_arm(manager, timer, 0, interval_ms, callback, ctx);
}

bool timer_cancel(timer_event_t* timer) {
    if (!timer || !timer->owner) return false;

    timer_manager_t* manager = timer->owner;
    acquire_qspinlock(&manager->lock);

    if (timer->owner != manager) {
        release_qspinlock(&manager->lock);
        return false;
    }

    ht_remove(&timer->node);
    timer->owner = nullptr;
    manager->active_timers--;

    release_qspinlock(&manager->lock);
    return true;
}

static void cascade(timer_manager_t* manager, struct hlist_head* tv, int index) {
    struct hlist_head* head = &tv[index];
    struct hlist_node* n;
    timer_event_t* timer;

    // Splice the entire bucket out
    struct hlist_head list = {head->first};
    if (head->first) head->first->pprev = &list.first;
    head->first = nullptr;

    ht_for_each_entry_safe(timer, n, &list, node) {
        ht_remove(&timer->node);
        internal_add_timer(manager, timer);
    }
}

void timer_manager_tick(timer_manager_t* manager) {
    if (!manager) return;

    uint64_t now = timer_get_time_ms();
    if (manager->active_timers == 0 || now < manager->next_expires_at) return;

    acquire_qspinlock(&manager->lock);

    while (manager->curr_time_ms <= now) {
        // Fast-forward
        if (manager->curr_time_ms < manager->next_expires_at) {
            uint64_t target = manager->next_expires_at;
            if (target > now) target = now;

            // Ensure we halt at the next cascade boundary
            uint64_t next_boundary = (manager->curr_time_ms + TVR_SIZE) & ~((uint64_t)TVR_MASK);
            if (target > next_boundary) target = next_boundary;

            manager->curr_time_ms = target;
        } else {
            ++manager->curr_time_ms;
        }

        uint64_t current_idx = manager->curr_time_ms & TVR_MASK;
        if (!current_idx && manager->curr_time_ms != 0) {
            struct hlist_head* wheels[] = {manager->tv2, manager->tv3, manager->tv4, manager->tv5};

            for (int i = 0; i < 4; i++) {
                int shift = TVR_BITS + (i * TVN_BITS);
                int idx   = (int)((manager->curr_time_ms >> shift) & TVN_MASK);

                cascade(manager, wheels[i], idx);

                // Stop cascading if the wheel didn't wrap
                if (idx != 0) break;
            }
        }

        // Isolate expired timers
        struct hlist_head work_list = {manager->tv1[current_idx].first};
        if (manager->tv1[current_idx].first)
            manager->tv1[current_idx].first->pprev = &work_list.first;
        manager->tv1[current_idx].first = nullptr;

        release_qspinlock(&manager->lock);

        struct hlist_node* n;
        timer_event_t* timer;
        ht_for_each_entry_safe(timer, n, &work_list, node) {
            ht_remove(&timer->node);

            if (timer->callback) timer->callback(timer->ctx);

            // Re-arm periodic timers
            acquire_qspinlock(&manager->lock);
            if (timer->interval > 0 && timer->owner == manager) {
                timer->expires_at = manager->curr_time_ms + timer->interval;
                internal_add_timer(manager, timer);

                if (timer->expires_at < manager->next_expires_at)
                    manager->next_expires_at = timer->expires_at;
            } else {
                timer->owner = nullptr;
                manager->active_timers--;
            }

            release_qspinlock(&manager->lock);
        }

        acquire_qspinlock(&manager->lock);
    }

    manager->next_expires_at = manager->curr_time_ms;
    release_qspinlock(&manager->lock);
}