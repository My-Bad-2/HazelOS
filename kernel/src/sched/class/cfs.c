#include <stdatomic.h>
#include <stdint.h>
#include <string.h>

#include "compiler.h"
#include "libs/log.h"
#include "libs/rb_tree.h"
#include "sched/process.h"
#include "sched/sched_class.h"

#define MIN_GRANULARITY_NS 2500000ul  // 2.5ms
#define YIELD_PENALTY_NS   2000000ul  // 2ms
#define INIT_VRUNTIME_NS   100000ul   // 100us

// misc/scripts/calculate_wmult.py
static const uint32_t prio_to_wmult[40] = {
    /* -20 */ 0x0000BCE5, /* -19 */ 0x0000EC1E,
    /* -18 */ 0x00012725, /* -17 */ 0x000170EF,
    /* -16 */ 0x0001CD2B, /* -15 */ 0x00024075,
    /* -14 */ 0x0002D093, /* -13 */ 0x000384B8,
    /* -12 */ 0x000465E6, /* -11 */ 0x00057F5F,
    /* -10 */ 0x0006DF37, /*  -9 */ 0x00089705,
    /*  -8 */ 0x000ABCC7, /*  -7 */ 0x000D6BF9,
    /*  -6 */ 0x0010C6F7, /*  -5 */ 0x0014F8B5,
    /*  -4 */ 0x001A36E2, /*  -3 */ 0x0020C49B,
    /*  -2 */ 0x0028F5C2, /*  -1 */ 0x00333333,
    /*   0 */ 0x00400000, /*   1 */ 0x00500000,
    /*   2 */ 0x00640000, /*   3 */ 0x007D0000,
    /*   4 */ 0x009C4000, /*   5 */ 0x00C34FFF,
    /*   6 */ 0x00F42400, /*   7 */ 0x01312D00,
    /*   8 */ 0x017D7840, /*   9 */ 0x01DCD64F,
    /*  10 */ 0x02540BE4, /*  11 */ 0x02E90EDD,
    /*  12 */ 0x03A35294, /*  13 */ 0x048C2739,
    /*  14 */ 0x05AF3107, /*  15 */ 0x071AFD49,
    /*  16 */ 0x08E1BC9B, /*  17 */ 0x0B1A2BC2,
    /*  18 */ 0x0DE0B6B3, /*  19 */ 0x1158E460,
};

struct cfs_config {
    size_t vruntime;
    size_t total_runtime;
    int nice;
    int nice_idx;
};

#define CFS_DATA(t)          ((struct cfs_config*)(t)->sched.payload)
#define CFS_VRUNTIME(t)      (CFS_DATA(t)->vruntime)
#define CFS_TOTAL_RUNTIME(t) (CFS_DATA(t)->total_runtime)
#define CFS_NICE(t)          (CFS_DATA(t)->nice)
#define CFS_NICE_IDX(t)      (CFS_DATA(t)->nice_idx)

static inline size_t calculate_weighted_delta(size_t delta, int nice_idx) {
    if (nice_idx < 0) {
        nice_idx = 0;
    }

    if (nice_idx > 39) {
        nice_idx = 39;
    }

    uint32_t wmult = prio_to_wmult[nice_idx];
    uint128_t v    = (uint128_t)delta * wmult;

    return (size_t)(v >> 32);
}

static void cfs_init_task(thread_t* t, va_list args) {
    memset(t->sched.payload, 0, SCHED_DATA_PAYLOAD_SIZE);
    t->sched.private_data = nullptr;

    int nice = va_arg(args, int);
    if (nice < -20) {
        nice = -20;
    }

    if (nice > 19) {
        nice = 19;
    }

    CFS_NICE(t)     = nice;
    CFS_NICE_IDX(t) = CFS_NICE(t) + 20;

    per_cpu_data_t* target = smp_get_core((t->assigned_cpu == UINT32_MAX) ? 0 : t->assigned_cpu);
    CFS_VRUNTIME(t)        = target->min_vruntime + INIT_VRUNTIME_NS;
}

static void cfs_renice_task(per_cpu_data_t* rq, thread_t* t, int nice) {
    // Lag = Thread_VRuntime - System_Min_VRuntime
    int64_t vruntime_lag = (int64_t)CFS_VRUNTIME(t) - (int64_t)rq->min_vruntime;

    // Formula: NewLag = OldLag * (NewInverseWeight / OldInverseWeight)
    uint32_t old_wmult = prio_to_wmult[CFS_NICE_IDX(t)];
    uint32_t new_wmult = prio_to_wmult[nice + 20];

    if (vruntime_lag != 0) {
        vruntime_lag = (int64_t)((uint128_t)vruntime_lag * new_wmult) / old_wmult;
    }

    CFS_VRUNTIME(t) = (size_t)((int64_t)rq->min_vruntime + vruntime_lag);
    CFS_NICE(t)     = nice;
    CFS_NICE_IDX(t) = nice + 20;
}

static inline bool vruntime_less(uint64_t a, uint64_t b) {
    return (int64_t)(a - b) < 0;
}

static void cfs_enqueue_task(per_cpu_data_t* rq, thread_t* t) {
    struct rb_node** link  = &rq->cfs_tree.rb_root.rb_node;
    struct rb_node* parent = nullptr;
    bool is_leftmost       = true;

    while (*link) {
        parent          = *link;
        thread_t* entry = rb_entry(parent, thread_t, rb_node);

        if (vruntime_less(CFS_VRUNTIME(t), CFS_VRUNTIME(entry)) ||
            (CFS_VRUNTIME(t) == CFS_VRUNTIME(entry) && t->kobj.koid < entry->kobj.koid)) {
            link = &parent->rb_left;
        } else {
            link        = &parent->rb_right;
            is_leftmost = false;
        }
    }

    rb_link_node(&t->rb_node, parent, link);
    rb_insert_color_cached(&t->rb_node, &rq->cfs_tree, is_leftmost);

    t->on_rq = true;

    atomic_fetch_add_explicit(&rq->cpu_load, t->avg_load, memory_order_relaxed);
}

static void cfs_dequeue_task(per_cpu_data_t* rq, thread_t* t) {
    rb_erase_cached(&t->rb_node, &rq->cfs_tree);
    rb_init_node(&t->rb_node);

    t->on_rq = false;

    size_t current_load = atomic_load_explicit(&rq->cpu_load, memory_order_relaxed);
    if (current_load >= t->avg_load) {
        atomic_fetch_sub_explicit(&rq->cpu_load, t->avg_load, memory_order_relaxed);
    } else {
        atomic_store_explicit(&rq->cpu_load, 0, memory_order_relaxed);
    }
}

static void cfs_yield_task(per_cpu_data_t*, thread_t* t) {
    size_t wpenalty = calculate_weighted_delta(YIELD_PENALTY_NS, CFS_NICE_IDX(t));
    CFS_VRUNTIME(t) += wpenalty;
}

static void cfs_task_tick(per_cpu_data_t* rq, thread_t* t, size_t now) {
    size_t delta = (now > t->last_start_time) ? (now - t->last_start_time) : 0;

    CFS_TOTAL_RUNTIME(t) += delta;

    size_t wdelta = calculate_weighted_delta(delta, CFS_NICE_IDX(t));
    CFS_VRUNTIME(t) += wdelta;

    size_t v_min         = CFS_VRUNTIME(t);
    struct rb_node* left = rb_first_cached(&rq->cfs_tree);

    if (left) {
        thread_t* leftmost = rb_entry(left, thread_t, rb_node);

        if (CFS_VRUNTIME(leftmost) < v_min) {
            v_min = CFS_VRUNTIME(leftmost);
        }
    }

    if (v_min > rq->min_vruntime) {
        rq->min_vruntime = v_min;
    }
}

static void cfs_task_unblock(per_cpu_data_t* rq, thread_t* t) {
    size_t thresh   = (MIN_GRANULARITY_NS * 2);
    size_t v_target = (rq->min_vruntime > thresh) ? (rq->min_vruntime - thresh) : 0;

    if (CFS_VRUNTIME(t) < v_target) {
        CFS_VRUNTIME(t) = v_target;
    }
}

static thread_t* cfs_pick_next_task(per_cpu_data_t* rq) {
    struct rb_node* leftmost = rb_first_cached(&rq->cfs_tree);
    if (!leftmost) {
        return nullptr;
    }
    return rb_entry(leftmost, thread_t, rb_node);
}

static thread_t* cfs_steal_task(per_cpu_data_t* busiest_cpu, per_cpu_data_t* this_cpu) {
    struct rb_node* node = rb_last(&busiest_cpu->cfs_tree.rb_root);
    thread_t* victim     = nullptr;

    while (node) {
        thread_t* t = rb_entry(node, thread_t, rb_node);

        bool affinity_ok = (t->affinity_mask & (1ul << this_cpu->cpu_idx));
        bool is_running  = (t->state == THREAD_RUNNING);

        if (affinity_ok && !is_running) {
            victim = t;
            break;
        }

        node = rb_prev(node);
    }

    if (victim) {
        cfs_dequeue_task(busiest_cpu, victim);
        busiest_cpu->thread_count--;

        victim->assigned_cpu = this_cpu->cpu_idx;

        int64_t vruntime_norm = (int64_t)CFS_VRUNTIME(victim) - (int64_t)busiest_cpu->min_vruntime;
        if (vruntime_norm < 0) {
            vruntime_norm = 0;
        }

        CFS_VRUNTIME(victim) = (size_t)((int64_t)this_cpu->min_vruntime + vruntime_norm);

        cfs_enqueue_task(this_cpu, victim);
        this_cpu->thread_count++;
    }

    return victim;
}

static bool cfs_check_preempt(thread_t* new_task, thread_t* curr_task) {
    if (CFS_VRUNTIME(new_task) < CFS_VRUNTIME(curr_task)) {
        size_t diff = CFS_VRUNTIME(curr_task) - CFS_VRUNTIME(new_task);
        return diff > MIN_GRANULARITY_NS;
    }

    return false;
}

struct sched_class cfs_sched_class = {
    .name      = "CFS",
    .priority  = 10,
    .policy_id = SCHED_NORMAL,
    .next      = nullptr,

    .init_task   = cfs_init_task,
    .renice_task = cfs_renice_task,

    .enqueue_task   = cfs_enqueue_task,
    .dequeue_task   = cfs_dequeue_task,
    .yield_task     = cfs_yield_task,
    .task_tick      = cfs_task_tick,
    .task_unblock   = cfs_task_unblock,
    .pick_next_task = cfs_pick_next_task,
    .steal_task     = cfs_steal_task,
    .check_preempt  = cfs_check_preempt
};