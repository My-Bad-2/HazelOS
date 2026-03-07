#include <stdatomic.h>

#include "drivers/timer.h"
#include "libs/log.h"
#include "libs/rb_tree.h"
#include "sched/sched_class.h"

#define RR_QUANTUM_NS 10000000ul

struct rt_config {
    size_t arrival_time;
    size_t time_slice;
    int priority;
};

#define RT_DATA(t)     ((struct rt_config*)(t)->sched.payload)
#define RT_ARRIVAL(t)  (RT_DATA(t)->arrival_time)
#define RT_SLICE(t)    (RT_DATA(t)->time_slice)
#define RT_PRIORITY(t) (RT_DATA(t)->priority)

static void rt_init_task(thread_t* t, va_list args) {
    RT_SLICE(t) = 0;

    if (t->policy != SCHED_RR) {
        return;
    }

    size_t now   = timer_get_time();
    int priority = va_arg(args, int);
    if (priority < 0) {
        priority = 0;
    }

    if (priority > 99) {
        priority = 99;
    }

    RT_PRIORITY(t) = priority;
    RT_ARRIVAL(t)  = now;

    if (t->policy == SCHED_RR && RT_SLICE(t) == 0) {
        RT_SLICE(t) = RR_QUANTUM_NS;
    }
}

static void rt_renice_task(per_cpu_data_t*, thread_t* t, int nice) {
    int new_prio = 50 - nice;

    if (new_prio < 0) {
        new_prio = 0;
    }

    if (new_prio > 99) {
        new_prio = 99;
    }

    RT_PRIORITY(t) = new_prio;
}

static void rt_enqueue_task(per_cpu_data_t* rq, thread_t* t) {
    struct rb_node** link  = &rq->rt_tree.rb_root.rb_node;
    struct rb_node* parent = nullptr;
    bool is_leftmost       = true;

    while (*link) {
        parent          = *link;
        thread_t* entry = rb_entry(parent, thread_t, rb_node);

        if (RT_PRIORITY(t) > RT_PRIORITY(entry) ||
            (RT_PRIORITY(t) == RT_PRIORITY(entry) && RT_ARRIVAL(t) < RT_ARRIVAL(entry))) {
            link = &parent->rb_left;
        } else {
            link        = &parent->rb_right;
            is_leftmost = false;
        }
    }

    rb_link_node(&t->rb_node, parent, link);
    rb_insert_color_cached(&t->rb_node, &rq->rt_tree, is_leftmost);

    t->on_rq = true;
    atomic_fetch_add_explicit(&rq->cpu_load, t->avg_load, memory_order_relaxed);
}

static void rt_dequeue_task(per_cpu_data_t* rq, thread_t* t) {
    rb_erase_cached(&t->rb_node, &rq->rt_tree);
    rb_init_node(&t->rb_node);

    t->on_rq = false;

    size_t current_load = atomic_load_explicit(&rq->cpu_load, memory_order_relaxed);
    if (current_load >= t->avg_load) {
        atomic_fetch_sub_explicit(&rq->cpu_load, t->avg_load, memory_order_relaxed);
    } else {
        atomic_store_explicit(&rq->cpu_load, 0, memory_order_relaxed);
    }
}

static void rt_yield_task(per_cpu_data_t* rq, thread_t* t) {
    RT_ARRIVAL(t) = timer_get_time();

    if (t->policy == SCHED_RR) {
        RT_SLICE(t) = RR_QUANTUM_NS;
    }

    rq->reschedule_needed = true;
}

static void rt_task_tick(per_cpu_data_t* rq, thread_t* t, size_t now) {
    if (t->policy != SCHED_RR) {
        return;
    }

    size_t delta = (now > t->last_start_time) ? (now - t->last_start_time) : 0;

    if (RT_SLICE(t) <= delta) {
        RT_SLICE(t)           = RR_QUANTUM_NS;
        RT_ARRIVAL(t)         = now;
        rq->reschedule_needed = true;
    } else {
        RT_SLICE(t) -= delta;
    }
}

static thread_t* rt_pick_next_task(per_cpu_data_t* rq) {
    struct rb_node* leftmost = rb_first_cached(&rq->rt_tree);

    if (!leftmost) {
        return nullptr;
    }

    return rb_entry(leftmost, thread_t, rb_node);
}

static thread_t* rt_steal_task(per_cpu_data_t* busiest_cpu, per_cpu_data_t* this_cpu) {
    struct rb_node* node = rb_last(&busiest_cpu->rt_tree.rb_root);
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
        rt_dequeue_task(busiest_cpu, victim);
        busiest_cpu->thread_count--;

        victim->assigned_cpu = this_cpu->cpu_idx;
        rt_enqueue_task(this_cpu, victim);
        this_cpu->thread_count++;
    }

    return victim;
}

static bool rt_check_preempt(thread_t* new_task, thread_t* curr_task) {
    return RT_PRIORITY(new_task) > RT_PRIORITY(curr_task);
}

struct sched_class rt_rr_sched_class = {
    .name      = "RT",
    .priority  = 50,
    .policy_id = SCHED_RR,
    .next      = nullptr,

    .init_task   = rt_init_task,
    .renice_task = rt_renice_task,

    .enqueue_task   = rt_enqueue_task,
    .dequeue_task   = rt_dequeue_task,
    .yield_task     = rt_yield_task,
    .task_tick      = rt_task_tick,
    .pick_next_task = rt_pick_next_task,
    .steal_task     = rt_steal_task,
    .check_preempt  = rt_check_preempt
};

struct sched_class rt_fifo_sched_class = {
    .name      = "FIFO",
    .priority  = 50,
    .policy_id = SCHED_FIFO,
    .next      = nullptr,

    .init_task   = rt_init_task,
    .renice_task = rt_renice_task,

    .enqueue_task   = rt_enqueue_task,
    .dequeue_task   = rt_dequeue_task,
    .yield_task     = rt_yield_task,
    .task_tick      = rt_task_tick,
    .pick_next_task = rt_pick_next_task,
    .steal_task     = rt_steal_task,
    .check_preempt  = rt_check_preempt
};