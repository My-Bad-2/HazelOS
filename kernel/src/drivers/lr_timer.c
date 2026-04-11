#include "drivers/internal/lr_timer.h"

#include <stdatomic.h>
#include <stdint.h>

#include "drivers/timer.h"
#include "libs/hashtable.h"
#include "libs/spinlock.h"

void lrtimer_manager_init(struct lrtimer_manager* manager) {
    if (!manager) return;

    ht_init_table(manager->tv1, TVR_SIZE);
    ht_init_table(manager->tv2, TVN_SIZE);
    ht_init_table(manager->tv3, TVN_SIZE);
    ht_init_table(manager->tv4, TVN_SIZE);
    ht_init_table(manager->tv5, TVN_SIZE);

    uint64_t ms = timer_get_time_ms();

    manager->curr_time_ms = ms;

    atomic_init(&manager->active_timers, 0);
    atomic_init(&manager->next_expires_at, ms);

    create_qspinlock(&manager->lock);
}

static void internal_add_timer(struct lrtimer_manager* manager, struct lrtimer_event* timer) {
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
    struct lrtimer_manager* manager,
    struct lrtimer_event* timer,
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

    uint64_t current_next = atomic_load_explicit(&manager->next_expires_at, memory_order_relaxed);
    size_t active         = atomic_load_explicit(&manager->active_timers, memory_order_relaxed);

    if (active == 0 || timer->expires_at < current_next)
        manager->next_expires_at = timer->expires_at;

    internal_add_timer(manager, timer);
    atomic_fetch_add_explicit(&manager->active_timers, 1, memory_order_relaxed);

    release_qspinlock(&manager->lock);
}

void lrtimer_arm_oneshot(
    struct lrtimer_manager* manager,
    struct lrtimer_event* timer,
    uint64_t delay_ms,
    timer_callback_t callback,
    void* ctx
) {
    __timer_arm(manager, timer, delay_ms, 0, callback, ctx);
}

void lrtimer_arm_periodic(
    struct lrtimer_manager* manager,
    struct lrtimer_event* timer,
    uint64_t interval_ms,
    timer_callback_t callback,
    void* ctx
) {
    __timer_arm(manager, timer, 0, interval_ms, callback, ctx);
}

bool lrtimer_cancel(struct lrtimer_event* timer) {
    if (!timer || !timer->owner) return false;

    struct lrtimer_manager* manager = timer->owner;
    acquire_qspinlock(&manager->lock);

    if (timer->owner != manager) {
        release_qspinlock(&manager->lock);
        return false;
    }

    ht_remove(&timer->node);
    timer->owner = nullptr;

    atomic_fetch_sub_explicit(&manager->active_timers, 1, memory_order_relaxed);

    release_qspinlock(&manager->lock);
    return true;
}

static void cascade(struct lrtimer_manager* manager, struct hlist_head* tv, int index) {
    struct hlist_head* head = &tv[index];
    struct hlist_node* n;
    struct lrtimer_event* timer;

    // Splice the entire bucket out
    struct hlist_head list = {head->first};
    if (head->first) head->first->pprev = &list.first;
    head->first = nullptr;

    ht_for_each_entry_safe(timer, n, &list, node) {
        ht_remove(&timer->node);
        internal_add_timer(manager, timer);
    }
}

void lrtimer_tick(struct lrtimer_manager* manager) {
    if (!manager) return;

    uint64_t now  = timer_get_time_ms();
    size_t active = atomic_load_explicit(&manager->active_timers, memory_order_acquire);
    uint64_t next = atomic_load_explicit(&manager->next_expires_at, memory_order_acquire);

    if (active == 0 || now < next) return;

    acquire_qspinlock(&manager->lock);

    while (manager->curr_time_ms <= now) {
        // Fast-forward
        uint64_t current_next =
            atomic_load_explicit(&manager->next_expires_at, memory_order_relaxed);

        if (manager->curr_time_ms < current_next) {
            uint64_t target = current_next;
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
        struct lrtimer_event* timer;
        ht_for_each_entry_safe(timer, n, &work_list, node) {
            ht_remove(&timer->node);

            if (timer->callback) timer->callback(timer->ctx);

            // Re-arm periodic timers
            acquire_qspinlock(&manager->lock);
            if (timer->interval > 0 && timer->owner == manager) {
                timer->expires_at = manager->curr_time_ms + timer->interval;
                internal_add_timer(manager, timer);

                uint64_t current_next_inner =
                    atomic_load_explicit(&manager->next_expires_at, memory_order_relaxed);
                if (timer->expires_at < current_next_inner)
                    atomic_store_explicit(
                        &manager->next_expires_at,
                        timer->expires_at,
                        memory_order_release
                    );
            } else {
                timer->owner = nullptr;
                atomic_fetch_sub_explicit(&manager->active_timers, 1, memory_order_relaxed);
            }

            release_qspinlock(&manager->lock);
        }

        acquire_qspinlock(&manager->lock);
    }

    atomic_store_explicit(&manager->next_expires_at, manager->curr_time_ms, memory_order_release);
    release_qspinlock(&manager->lock);
}