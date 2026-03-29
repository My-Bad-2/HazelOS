#include <stdatomic.h>
#include <stdint.h>
#include <string.h>

#include "drivers/timer.h"
#include "libs/dlist.h"
#include "libs/rb_tree.h"
#include "sched/sched_class.h"

#define RR_QUANTUM_NS 10000000ul  // 10ms default quantum for Round Robin

struct rt_config {
    uint64_t arrival_time;
    int64_t time_slice;
    int priority;
};

#define RT_DATA(t)     ((struct rt_config*)(t)->sched.payload)
#define RT_ARRIVAL(t)  (RT_DATA(t)->arrival_time)
#define RT_SLICE(t)    (RT_DATA(t)->time_slice)
#define RT_PRIORITY(t) (RT_DATA(t)->priority)

static void rt_init_task(thread_t* t, va_list args) {
    memset(t->sched.payload, 0, SCHED_DATA_PAYLOAD_SIZE);

    int priority = va_arg(args, int);
    if (priority < 0) priority = 0;
    if (priority > 99) priority = 99;

    RT_PRIORITY(t) = priority;
    RT_ARRIVAL(t)  = timer_get_time();
    RT_SLICE(t)    = (t->policy == SCHED_RR) ? RR_QUANTUM_NS : 0;
}

static void rt_renice_task(per_cpu_data_t*, thread_t* t, int nice) {
    int new_prio = 50 - nice;
    if (new_prio < 0) new_prio = 0;
    if (new_prio > 99) new_prio = 99;

    RT_PRIORITY(t) = new_prio;
}

static void rt_enqueue_task(per_cpu_data_t* rq, thread_t* t) {
    // Priority 99 goes to Index 0. Priority 0 goes to Index 99.
    int idx = 99 - RT_PRIORITY(t);

    dlist_add_tail(&t->run_node, &rq->rt_queues[idx]);

    rq->rt_bitmap[idx / 64] |= (1ULL << (idx % 64));
    rq->rt_thread_count++;
    t->on_rq = true;

    atomic_fetch_add_explicit(&rq->cpu_load, t->avg_load, memory_order_relaxed);
}

static void rt_dequeue_task(per_cpu_data_t* rq, thread_t* t) {
    int idx = 99 - RT_PRIORITY(t);

    dlist_del_init(&t->run_node);

    if (dlist_empty(&rq->rt_queues[idx])) rq->rt_bitmap[idx / 64] &= ~(1ULL << (idx % 64));

    rq->rt_thread_count--;
    t->on_rq = false;

    size_t current_load = atomic_load_explicit(&rq->cpu_load, memory_order_relaxed);
    if (current_load >= t->avg_load)
        atomic_fetch_sub_explicit(&rq->cpu_load, t->avg_load, memory_order_relaxed);
    else
        atomic_store_explicit(&rq->cpu_load, 0, memory_order_relaxed);
}

static void rt_yield_task(per_cpu_data_t* rq, thread_t* t) {
    // Yielding a FIFO or RR thread puts it at the back of its priority tier
    RT_ARRIVAL(t) = timer_get_time();
    if (t->policy == SCHED_RR) RT_SLICE(t) = RR_QUANTUM_NS;
    rq->reschedule_needed = true;
}

static void rt_task_tick(per_cpu_data_t* rq, thread_t* t, size_t now) {
    // SCHED_FIFO runs until it blocks, yields, or is preempted
    if (t->policy != SCHED_RR) return;

    int64_t delta = (now > t->last_start_time) ? (int64_t)(now - t->last_start_time) : 0;

    t->last_start_time = now;

    RT_SLICE(t) -= delta;

    if (RT_SLICE(t) <= 0) {
        RT_SLICE(t)           = RR_QUANTUM_NS;
        RT_ARRIVAL(t)         = now;
        rq->reschedule_needed = true;
    }
}

static thread_t* rt_pick_next_task(per_cpu_data_t* rq) {
    if (unlikely(rq->rt_thread_count == 0)) {
        return nullptr;
    }

    int idx;
    if (rq->rt_bitmap[0] != 0)
        idx = ffs((long)rq->rt_bitmap[0]) - 1;
    else
        idx = ffs((long)rq->rt_bitmap[1]) - 1 + 64;

    return dlist_first_entry(&rq->rt_queues[idx], thread_t, run_node);
}

static thread_t* rt_steal_task(per_cpu_data_t* busiest_cpu, per_cpu_data_t* this_cpu) {
    if (busiest_cpu->rt_thread_count == 0) return nullptr;

    thread_t* victim = nullptr;
    for (int i = 99; i >= 0; --i) {
        if ((busiest_cpu->rt_bitmap[i / 64] & (1ULL << (i % 64))) == 0) continue;

        struct dlist_head* pos;
        dlist_for_each_prev(pos, &busiest_cpu->rt_queues[i]) {
            thread_t* t = dlist_entry(pos, thread_t, run_node);

            if (likely(t->state != THREAD_RUNNING) &&
                (t->affinity_mask & (1ul << this_cpu->cpu_idx))) {
                victim = t;
                goto found_victim;
            }
        }
    }

found_victim:
    if (victim) {
        rt_dequeue_task(busiest_cpu, victim);

        victim->assigned_cpu = this_cpu->cpu_idx;
        rt_enqueue_task(this_cpu, victim);
    }

    return victim;
}

static bool rt_check_preempt(thread_t* new_task, thread_t* curr_task) {
    // RT tasks only preempt if they are strictly higher priority
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