#include <stdatomic.h>

#include "drivers/timer.h"
#include "libs/log.h"
#include "libs/rb_tree.h"
#include "sched/sched_class.h"

struct dl_config {
    size_t deadline;
    size_t period;
    size_t runtime;
    size_t remaining;
};

#define DL_DATA(t)      ((struct dl_config*)(t)->sched.payload)
#define DL_DEADLINE(t)  (DL_DATA(t)->deadline)
#define DL_PERIOD(t)    (DL_DATA(t)->period)
#define DL_RUNTIME(t)   (DL_DATA(t)->runtime)
#define DL_REMAINING(t) (DL_DATA(t)->remaining)

static void dl_init_task(thread_t* t, va_list args) {
    size_t now = timer_get_time();

    DL_RUNTIME(t)   = va_arg(args, size_t);
    DL_PERIOD(t)    = va_arg(args, size_t);
    DL_DEADLINE(t)  = now + DL_PERIOD(t);
    DL_REMAINING(t) = DL_RUNTIME(t);
}

static void dl_renice_task(per_cpu_data_t*, thread_t* t, int) {
    KLOG_WARN("SCHED: Ignoring renice on Deadline task TID=%d\n", t->tid);
}

static void dl_enqueue_task(per_cpu_data_t* rq, thread_t* t) {
    struct rb_node** link  = &rq->dl_tree.rb_root.rb_node;
    struct rb_node* parent = nullptr;
    bool is_leftmost       = true;

    while (*link) {
        parent          = *link;
        thread_t* entry = rb_entry(parent, thread_t, rb_node);

        if (DL_DEADLINE(t) < DL_DEADLINE(entry)) {
            link = &parent->rb_left;
        } else {
            link        = &parent->rb_right;
            is_leftmost = false;
        }
    }

    rb_link_node(&t->rb_node, parent, link);
    rb_insert_color_cached(&t->rb_node, &rq->dl_tree, is_leftmost);

    t->on_rq = true;
    atomic_fetch_add_explicit(&rq->cpu_load, t->avg_load, memory_order_relaxed);
}

static void dl_dequeue_task(per_cpu_data_t* rq, thread_t* t) {
    rb_erase_cached(&t->rb_node, &rq->dl_tree);
    rb_init_node(&t->rb_node);

    t->on_rq = false;

    size_t current_load = atomic_load_explicit(&rq->cpu_load, memory_order_relaxed);
    if (current_load >= t->avg_load) {
        atomic_fetch_sub_explicit(&rq->cpu_load, t->avg_load, memory_order_relaxed);
    } else {
        atomic_store_explicit(&rq->cpu_load, 0, memory_order_relaxed);
    }
}

static void dl_yield_task(per_cpu_data_t* rq, thread_t* t) {
    DL_REMAINING(t) = DL_RUNTIME(t);
    DL_DEADLINE(t) += DL_PERIOD(t);

    size_t now = timer_get_time();
    if (DL_DEADLINE(t) < now) {
        DL_DEADLINE(t) = now + DL_PERIOD(t);
    }

    rq->reschedule_needed = true;
}

static void dl_task_tick(per_cpu_data_t* rq, thread_t* t, size_t now) {
    size_t delta = (now > t->last_start_time) ? (now - t->last_start_time) : 0;

    if (DL_REMAINING(t) > delta) {
        DL_REMAINING(t) -= delta;
    } else {
        DL_REMAINING(t) = DL_RUNTIME(t);
        DL_DEADLINE(t) += DL_PERIOD(t);

        if (DL_DEADLINE(t) < now) {
            DL_DEADLINE(t) = now + DL_PERIOD(t);
        }

        rq->reschedule_needed = true;
    }
}

static void dl_task_unblock(per_cpu_data_t*, thread_t* t) {
    size_t now = timer_get_time();

    if (DL_DEADLINE(t) < now) {
        DL_DEADLINE(t)  = now + DL_PERIOD(t);
        DL_REMAINING(t) = DL_RUNTIME(t);
    }
}

static thread_t* dl_pick_next_task(per_cpu_data_t* rq) {
    struct rb_node* leftmost = rb_first_cached(&rq->dl_tree);
    if (!leftmost) {
        return nullptr;
    }

    return rb_entry(leftmost, thread_t, rb_node);
}

static thread_t* dl_steal_task(per_cpu_data_t* busiest_cpu, per_cpu_data_t* this_cpu) {
    struct rb_node* node = rb_last(&busiest_cpu->dl_tree.rb_root);
    thread_t* victim     = nullptr;

    while (node) {
        thread_t* t = rb_entry(node, thread_t, rb_node);

        if ((t->affinity_mask & (1ul << this_cpu->cpu_idx)) && (t->state != THREAD_RUNNING)) {
            victim = t;
            break;
        }

        node = rb_prev(node);
    }

    if (victim) {
        dl_dequeue_task(busiest_cpu, victim);
        busiest_cpu->thread_count--;

        victim->assigned_cpu = this_cpu->cpu_idx;
        dl_enqueue_task(this_cpu, victim);
        this_cpu->thread_count++;
    }

    return victim;
}

static bool dl_check_preempt(thread_t* new_task, thread_t* curr_task) {
    return DL_DEADLINE(new_task) < DL_DEADLINE(curr_task);
}

struct sched_class dl_sched_class = {
    .name      = "DEADLINE",
    .priority  = 99,
    .policy_id = SCHED_DEADLINE,
    .next      = nullptr,

    .init_task   = dl_init_task,
    .renice_task = dl_renice_task,

    .enqueue_task   = dl_enqueue_task,
    .dequeue_task   = dl_dequeue_task,
    .yield_task     = dl_yield_task,
    .task_tick      = dl_task_tick,
    .task_unblock   = dl_task_unblock,
    .pick_next_task = dl_pick_next_task,
    .steal_task     = dl_steal_task,
    .check_preempt  = dl_check_preempt
};