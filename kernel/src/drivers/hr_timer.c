#include "drivers/internal/hr_timer.h"

#include "drivers/timer.h"

void hrtimer_manager_init(struct hrtimer_manager* manager) {
    if (!manager) return;

    manager->root = RB_ROOT_CACHED;

    atomic_init(&manager->next_expires_ns, UINT64_MAX);
    atomic_init(&manager->active_timers, 0);

    create_qspinlock(&manager->lock);
}

static void internal_enqueue_timer(struct hrtimer_manager* manager, struct hrtimer_event* timer) {
    struct rb_node** link  = &manager->root.rb_root.rb_node;
    struct rb_node* parent = nullptr;
    bool leftmost          = true;

    while (*link) {
        parent                      = *link;
        struct hrtimer_event* entry = rb_entry(parent, struct hrtimer_event, node);

        if (timer->expires_ns < entry->expires_ns) {
            link = &parent->rb_left;
        } else {
            link     = &parent->rb_right;
            leftmost = false;
        }
    }

    rb_link_node(&timer->node, parent, link);
    rb_insert_color_cached(&timer->node, &manager->root, leftmost);

    if (leftmost)
        atomic_store_explicit(&manager->next_expires_ns, timer->expires_ns, memory_order_release);
}

static void __hrtimer_arm(
    struct hrtimer_manager* manager,
    struct hrtimer_event* timer,
    uint64_t delay_ns,
    uint64_t interval_ns,
    timer_callback_t cb,
    void* ctx
) {
    if (!manager || !timer) return;

    acquire_qspinlock(&manager->lock);
    RB_CLEAR_NODE(&timer->node);

    timer->callback    = cb;
    timer->ctx         = ctx;
    timer->interval_ns = interval_ns;
    timer->owner       = manager;
    timer->expires_ns  = timer_get_time() + delay_ns;

    internal_enqueue_timer(manager, timer);
    atomic_fetch_add_explicit(&manager->active_timers, 1, memory_order_relaxed);
    release_qspinlock(&manager->lock);
}

void hrtimer_arm_oneshot(
    struct hrtimer_manager* manager,
    struct hrtimer_event* timer,
    uint64_t delay_ns,
    timer_callback_t cb,
    void* ctx
) {
    __hrtimer_arm(manager, timer, delay_ns, 0, cb, ctx);
}

void hrtimer_arm_periodic(
    struct hrtimer_manager* manager,
    struct hrtimer_event* timer,
    uint64_t interval_ns,
    timer_callback_t cb,
    void* ctx
) {
    __hrtimer_arm(manager, timer, interval_ns, interval_ns, cb, ctx);
}

bool hrtimer_cancel(struct hrtimer_event* timer) {
    if (!timer || !timer->owner) return false;

    struct hrtimer_manager* manager = timer->owner;
    acquire_qspinlock(&manager->lock);

    if (timer->owner != manager) {
        release_qspinlock(&manager->lock);
        return false;
    }

    if (!RB_EMPTY_NODE(&timer->node)) {
        rb_erase_cached(&timer->node, &manager->root);
        RB_CLEAR_NODE(&timer->node);

        struct rb_node* leftmost = rb_first_cached(&manager->root);
        if (leftmost) {
            struct hrtimer_event* next = rb_entry(leftmost, struct hrtimer_event, node);
            atomic_store_explicit(
                &manager->next_expires_ns,
                next->expires_ns,
                memory_order_release
            );
        } else {
            atomic_store_explicit(&manager->next_expires_ns, UINT64_MAX, memory_order_release);
        }
    }

    timer->owner = nullptr;
    atomic_fetch_sub_explicit(&manager->active_timers, 1, memory_order_relaxed);

    release_qspinlock(&manager->lock);
    return true;
}

void hrtimer_interrupt_tick(struct hrtimer_manager* manager) {
    if (!manager) return;

    uint64_t now = timer_get_time();

    size_t active = atomic_load_explicit(&manager->active_timers, memory_order_acquire);
    uint64_t next = atomic_load_explicit(&manager->next_expires_ns, memory_order_acquire);

    if (active == 0 || now < next) return;

    acquire_qspinlock(&manager->lock);

    while (true) {
        struct rb_node* node = rb_first_cached(&manager->root);
        if (!node) break;

        struct hrtimer_event* timer = rb_entry(node, struct hrtimer_event, node);

        // If the earliest timer is still in the future, we are done
        if (timer->expires_ns > now) break;

        rb_erase_cached(node, &manager->root);
        RB_CLEAR_NODE(node);

        release_qspinlock(&manager->lock);

        if (timer->callback) timer->callback(timer->ctx);

        acquire_qspinlock(&manager->lock);

        if (timer->interval_ns > 0 && timer->owner == manager) {
            timer->expires_ns += timer->interval_ns;

            if (timer->expires_ns <= now) {
                uint64_t overruns = (now - timer->expires_ns) / timer->interval_ns;
                timer->expires_ns += (overruns + 1) * timer->interval_ns;
            }

            internal_enqueue_timer(manager, timer);
        } else {
            timer->owner = nullptr;
            atomic_fetch_sub_explicit(&manager->active_timers, 1, memory_order_relaxed);
        }

        // Refresh 'now' in case a callback took a significant amount of time to execute
        now = timer_get_time();
    }

    struct rb_node* leftmost = rb_first_cached(&manager->root);
    if (leftmost) {
        struct hrtimer_event* next_timer = rb_entry(leftmost, struct hrtimer_event, node);
        atomic_store_explicit(
            &manager->next_expires_ns,
            next_timer->expires_ns,
            memory_order_release
        );
    } else {
        atomic_store_explicit(&manager->next_expires_ns, UINT64_MAX, memory_order_release);
    }

    release_qspinlock(&manager->lock);
}