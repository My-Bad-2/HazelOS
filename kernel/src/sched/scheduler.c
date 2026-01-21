#include "sched/scheduler.h"

#include <errno.h>
#include <stdatomic.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "arch.h"
#include "boot/boot.h"
#include "compiler.h"
#include "cpu/exception.h"
#include "cpu/gdt.h"
#include "cpu/lapic.h"
#include "cpu/mask.h"
#include "cpu/registers.h"
#include "cpu/smp.h"
#include "drivers/arch_timer.h"
#include "drivers/timer.h"
#include "libs/log.h"
#include "libs/rb_tree.h"
#include "libs/spinlock.h"
#include "sched/process.h"

#define LOAD_BALANCE_INTERVAL 1000
#define SCHEDULER_LATENCY     20
#define CACHE_HOT_THRESHOLD   1

#define DEFAULT_NICE 0

#define PELT_HALF_LIFE_MS 32
#define PELT_MAX_LOAD     1024
#define MIGRATION_COST_NS 50000  // 50us

#define MIN_GRANULARITY_NS 2500000ul   // 2.5ms
#define TARGET_LATENCY_NS  20000000ul  // 20ms
#define RR_QUANTUM_NS      10000000ul  // 10ms
#define YIELD_PENALTY_NS   2000000ul   // 2ms

#define LOAD_AVG_PERIOD 32
#define LOAD_AVG_MAX    47742

#define COST_IDLE_CORE   0     // Gold standard
#define COST_SMT_THREAD  500   // Sibling is busy (50% capacity penalty)
#define COST_BUSY_THREAD 1000  // CPU is fully utilized

static process_t* kernel_proc = nullptr;
static bool initialized       = false;

static uint32_t cpu_count = 0;

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

// misc/scripts/calculate_pelt.py
static const uint16_t pelt_decay_factors[32] = {
    /*  0ms */ 0x8000, /*  1ms */ 0x7d42, /*  2ms */ 0x7a93, /*  3ms */ 0x77f2,
    /*  4ms */ 0x7560, /*  5ms */ 0x72dd, /*  6ms */ 0x7066, /*  7ms */ 0x6dfe,
    /*  8ms */ 0x6ba2, /*  9ms */ 0x6954, /* 10ms */ 0x6712, /* 11ms */ 0x64dd,
    /* 12ms */ 0x62b4, /* 13ms */ 0x6096, /* 14ms */ 0x5e84, /* 15ms */ 0x5c7e,
    /* 16ms */ 0x5a82, /* 17ms */ 0x5892, /* 18ms */ 0x56ac, /* 19ms */ 0x54d1,
    /* 20ms */ 0x52ff, /* 21ms */ 0x5138, /* 22ms */ 0x4f7b, /* 23ms */ 0x4dc7,
    /* 24ms */ 0x4c1c, /* 25ms */ 0x4a7a, /* 26ms */ 0x48e2, /* 27ms */ 0x4752,
    /* 28ms */ 0x45cb, /* 29ms */ 0x444c, /* 30ms */ 0x42d5, /* 31ms */ 0x4167,
};

// CPU PELT Lookup Table (Half-life: 32ms)
// Base Factor (y): 0.97857206
static const uint32_t runnable_avg_yN_inv[] = {
    0xffffffff, 0xfa83b2db, 0xf5257d15, 0xefe4b99b,  // 0-3
    0xeac0c6e7, 0xe5b906e7, 0xe0ccdeec, 0xdbfbb797,  // 4-7
    0xd744fcca, 0xd2a81d91, 0xce248c15, 0xc9b9bd86,  // 8-11
    0xc5672a11, 0xc12c4cca, 0xbd08a39f, 0xb8fbaf47,  // 12-15
    0xb504f333, 0xb123f581, 0xad583eea, 0xa9a15ab4,  // 16-19
    0xa5fed6a9, 0xa2704303, 0x9ef53260, 0x9b8d39b9,  // 20-23
    0x9837f051, 0x94f4efa8, 0x91c3d373, 0x8ea4398b,  // 24-27
    0x8b95c1e3, 0x88980e80, 0x85aac367, 0x82cd8698,  // 28-31
};

void arch_switch_context(switch_context_t** prev, switch_context_t* next);

static void idle_task_entry(void*) {
    arch_halt(true);
}

static bool is_cpu_idle(per_cpu_data_t* cpu) {
    return cpu->curr_thread == cpu->idle_thread;
}

static inline size_t calculate_weighted_delta(size_t delta, int nice_idx) {
    if (nice_idx < 0) {
        nice_idx = 0;
    }

    if (nice_idx > 39) {
        nice_idx = 39;
    }

    uint32_t wmult = prio_to_wmult[nice_idx];

    uint128_t v = (uint128_t)delta * wmult;

    return (size_t)(v >> 32);
}

static inline size_t get_time_now(void) {
    return timer_get_time();
}

static void sleep_callback(void* ctx) {
    thread_t* t = (thread_t*)ctx;

    if (t && t->state == THREAD_SLEEPING) {
        scheduler_unblock(t);
    }
}

void scheduler_init(void) {
    kernel_proc = process_create(true);

    if (!kernel_proc) {
        if (errno == 0) {
            errno = ENOMEM;
        }

        KLOG_ERROR("SCHED: failed to create kernel process errno=%d\n", errno);
        return;
    }

    cpu_count = (uint32_t)mp_request.response->cpu_count;

    thread_create_args_t idle_args = {
        .proc   = kernel_proc,
        .entry  = idle_task_entry,
        .arg    = nullptr,
        .policy = SCHED_NORMAL,
        .normal = {.nice = 19},
    };

    for (uint32_t i = 0; i < cpu_count; ++i) {
        per_cpu_data_t* cpu = smp_get_core(i);

        cpu->cfs_tree = RB_ROOT_CACHED;
        cpu->dl_tree  = RB_ROOT_CACHED;
        cpu->rt_tree  = RB_ROOT_CACHED;

        cpu->min_vruntime      = 0;
        cpu->balance_counter   = 0;
        cpu->reschedule_needed = false;
        atomic_store_explicit(&cpu->cpu_load, 0, memory_order_relaxed);

        thread_t* idle = thread_create(&idle_args);

        if (!idle) {
            int err = errno ? errno : EINVAL;
            PANIC("SCHED: failed to create idle thread cpu=%u errno=%d\n", i, err);
        }

        idle->state         = THREAD_READY;
        idle->assigned_cpu  = i;
        idle->affinity_mask = (1u << i);
        idle->on_rq         = false;

        cpu->idle_thread  = idle;
        cpu->curr_thread  = idle;
        cpu->thread_count = 0;
    }

    timer_configure(TIMER_PERIODIC, IRQ_TIMER, 1);

    initialized = true;

    KLOG_INFO("SCHED: initialized cpus=%u\n", cpu_count);
}

static void remove_from_runqueue(per_cpu_data_t* cpu, thread_t* t) {
    if (t->policy == SCHED_DEADLINE) {
        rb_erase_cached(&t->rb_node, &cpu->dl_tree);
    } else if (t->policy == SCHED_NORMAL) {
        rb_erase_cached(&t->rb_node, &cpu->cfs_tree);
    } else {
        rb_erase_cached(&t->rb_node, &cpu->rt_tree);
    }

    rb_init_node(&t->rb_node);

    size_t cpu_load = atomic_load_explicit(&cpu->cpu_load, memory_order_relaxed);

    if (cpu_load >= t->avg_load) {
        atomic_fetch_sub_explicit(&cpu->cpu_load, t->avg_load, memory_order_relaxed);
    } else {
        atomic_store_explicit(&cpu->cpu_load, 0, memory_order_relaxed);
    }
}

static inline bool sched_before(thread_t* t, thread_t* entry) {
    if (t->policy == SCHED_DEADLINE) {
        if (DL_DEADLINE(t) != DL_DEADLINE(entry)) {
            return DL_DEADLINE(t) < DL_DEADLINE(entry);
        }
    } else if (t->policy == SCHED_NORMAL) {
        if (CFS_VRUNTIME(t) != CFS_VRUNTIME(entry)) {
            return CFS_VRUNTIME(t) < CFS_VRUNTIME(entry);
        }
    } else {
        if (RT_PRIORITY(t) != RT_PRIORITY(entry)) {
            return RT_PRIORITY(t) > RT_PRIORITY(entry);
        }

        if (RT_ARRIVAL(t) != RT_ARRIVAL(entry)) {
            return RT_ARRIVAL(t) < RT_ARRIVAL(entry);
        }
    }

    return t->tid < entry->tid;
}

static void add_to_runqueue(per_cpu_data_t* cpu, thread_t* t) {
    struct rb_root_cached* root = nullptr;

    if (t->policy == SCHED_DEADLINE) {
        root = &cpu->dl_tree;
    } else if (t->policy == SCHED_NORMAL) {
        root = &cpu->cfs_tree;
    } else {
        root = &cpu->rt_tree;
    }

    struct rb_node** link  = &root->rb_root.rb_node;
    struct rb_node* parent = nullptr;
    bool is_leftmost       = true;

    while (*link) {
        parent          = *link;
        thread_t* entry = rb_entry(parent, thread_t, rb_node);

        if (sched_before(t, entry)) {
            link = &parent->rb_left;
        } else {
            link        = &parent->rb_right;
            is_leftmost = false;
        }
    }

    rb_link_node(&t->rb_node, parent, link);
    rb_insert_color_cached(&t->rb_node, root, is_leftmost);

    atomic_fetch_add_explicit(&cpu->cpu_load, t->avg_load, memory_order_relaxed);
}

static inline void update_dl_entity(thread_t* curr, size_t delta) {
    if (curr->policy != SCHED_DEADLINE) {
        return;
    }

    if (DL_REMAINING(curr) > delta) {
        DL_RUNTIME(curr) -= delta;
    } else {
        DL_REMAINING(curr) = DL_RUNTIME(curr);
        DL_DEADLINE(curr) += DL_PERIOD(curr);

        size_t now = get_time_now();

        if (DL_DEADLINE(curr) < now) {
            DL_DEADLINE(curr) = now + DL_PERIOD(curr);
        }

        smp_current_core()->reschedule_needed = true;
    }
}

static inline size_t decay_load(size_t load, size_t delta_ms) {
    if (delta_ms == 0) {
        return load;
    }

    // 2048 ms = 64 half lives
    if (delta_ms >= 2048) {
        return 0;
    }

    size_t half_lives = delta_ms / 32;
    size_t remainder  = delta_ms % 32;

    // Formula: (Load * Factor) / 0x8000
    size_t decayed = (load * pelt_decay_factors[remainder]) >> 15;
    return decayed >> half_lives;
}

static inline size_t decay_cpu_load(size_t val, size_t n) {
    if (n == 0) {
        return val;
    }

    if (n >= 32) {
        val >>= (n / 32);
        n %= 32;
    }

    size_t factor = runnable_avg_yN_inv[n];
    val           = (size_t)(((uint128_t)val * factor) >> 32);

    return val;
}

static void update_thread_load(thread_t* t) {
    size_t now = get_time_now();

    size_t delta_ns = now - t->last_load_update;
    size_t delta_ms = delta_ns / 1000000;

    if (delta_ms == 0) {
        return;
    }

    t->last_load_update = now;

    size_t decayed_load = decay_load(t->avg_load, delta_ms);

    // If running: Contribute 1024 (Full load) else 0
    size_t contribution = 0;
    if (t->state == THREAD_RUNNING) {
        size_t decayed_max = decay_load(PELT_MAX_LOAD, delta_ms);
        contribution       = PELT_MAX_LOAD - decayed_max;
    }

    t->avg_load = decayed_load + contribution;

    if (t->avg_load > PELT_MAX_LOAD) {
        t->avg_load = PELT_MAX_LOAD;
    }
}

static uint32_t select_best_cpu(thread_t* t) {
    per_cpu_data_t* curr_cpu = smp_current_core();

    if (curr_cpu->thread_count == 1 && (t->affinity_mask & (1ul << curr_cpu->cpu_idx))) {
        return curr_cpu->cpu_idx;
    }

    if (t->assigned_cpu != -1 && (t->affinity_mask & (1ul << t->assigned_cpu))) {
        per_cpu_data_t* prev = smp_current_core();

        if (prev->thread_count == 0) {
            return t->assigned_cpu;
        }

        size_t sibs        = cpumask_get(&prev->topology.core_siblings, prev->cpu_idx);
        bool are_sibs_busy = false;

        while (sibs) {
            int idx = ctz(sibs);

            if (smp_get_core((uint32_t)idx)->thread_count > 0) {
                are_sibs_busy = true;
            }

            sibs &= ~(1ul << idx);
        }

        if (!are_sibs_busy) {
            return t->assigned_cpu;
        }
    }

    uint32_t best_cpu = (uint32_t)(-1);
    size_t min_cost   = UINT64_MAX;

    for (uint32_t i = 0; i < cpu_count; ++i) {
        if (!((t->affinity_mask >> i) & 1)) {
            continue;
        }

        per_cpu_data_t* cpu = smp_get_core(i);
        size_t curr_cost    = 0;

        curr_cost += atomic_load_explicit(&cpu->cpu_load, memory_order_relaxed);
        curr_cost += ((size_t)cpu->thread_count * 100);

        size_t sibs = cpumask_get(&cpu->topology.core_siblings, i);

        while (sibs) {
            int idx                 = ctz(sibs);
            per_cpu_data_t* sibling = smp_get_core((uint32_t)idx);

            if (sibling->thread_count > 0) {
                curr_cost += COST_SMT_THREAD;
                curr_cost += (atomic_load_explicit(&sibling->cpu_load, memory_order_relaxed) / 2);
            }

            sibs &= ~(1ul << idx);
        }

        if (i != t->assigned_cpu) {
            per_cpu_data_t* last = smp_get_core(t->assigned_cpu);

            if (last && cpumask_test(&cpu->topology.llc_siblings, t->assigned_cpu)) {
                curr_cost += (MIGRATION_COST_NS / 2000);  // Small penalty on L3 hit
            } else {
                curr_cost += (MIGRATION_COST_NS / 1000);
            }
        }

        if (curr_cost < min_cost) {
            min_cost = curr_cost;
            best_cpu = i;
        }
    }

    if (best_cpu == (uint32_t)-1) {
        return (t->assigned_cpu != -1) ? t->assigned_cpu : 0;
    }

    return best_cpu;
}

// Priority: Deadline (3) > RT (2) > CFS (1) > Idle/Other (0)
static inline int sched_get_class(const thread_t* t) {
    int class = 0;
    if (!t) {
        goto cleanup;
    }

    if (t->policy == SCHED_DEADLINE) {
        class = 3;
        goto cleanup;
    }

    if (t->policy == SCHED_FIFO || t->policy == SCHED_RR) {
        class = 2;
        goto cleanup;
    }

    if (t->policy == SCHED_NORMAL) {
        class = 1;
    }

cleanup:
    return class;
}

static bool sched_should_preempt(thread_t* t, thread_t* curr) {
    if (!curr) {
        return true;
    }

    if (curr->state != THREAD_RUNNING) {
        return true;
    }

    int new_class  = sched_get_class(t);
    int curr_class = sched_get_class(curr);

    // Rule 1: Higher Scheduling class always preempts lower
    if (new_class > curr_class) {
        return true;
    }

    if (new_class < curr_class) {
        return false;
    }

    switch (new_class) {
        case 3:
            // Preempt if new thread has an earlier deadline
            return DL_DEADLINE(t) < DL_DEADLINE(curr);
        case 2:
            // preempt if new thread is of higher priority
            return RT_PRIORITY(t) > RT_PRIORITY(curr);
        case 1:
            // Wakup Granularity: Preempt only if difference is significant
            if (CFS_VRUNTIME(t) < CFS_VRUNTIME(curr)) {
                size_t diff = CFS_VRUNTIME(curr) - CFS_VRUNTIME(t);
                return diff > MIN_GRANULARITY_NS;
            }

            return false;
        default:
            break;
    }

    return true;
}

void scheduler_add_thread(thread_t* t) {
    if (!t) {
        errno = EINVAL;
        KLOG_WARN("SCHED: add_thread called with null thread\n");
        return;
    }

    update_thread_load(t);

    if (t->assigned_cpu == UINT32_MAX) {
        t->assigned_cpu = select_best_cpu(t);
    }

    per_cpu_data_t* cpu = smp_get_core(t->assigned_cpu);
    t->state            = THREAD_READY;
    t->on_rq            = true;

    if (t->policy == SCHED_NORMAL) {
        if (CFS_NICE(t) < -20) {
            CFS_NICE(t) = -20;
        }

        if (CFS_NICE(t) > 19) {
            CFS_NICE(t) = 19;
        }

        CFS_NICE_IDX(t) = CFS_NICE(t) + 20;
    }

    if (t->policy == SCHED_RR && RT_SLICE(t) == 0) {
        RT_SLICE(t) = RR_QUANTUM_NS;
    }

    acquire_interrupt_lock(&cpu->lock);

    size_t now = get_time_now();

    if (t->policy == SCHED_DEADLINE) {
        DL_DEADLINE(t)  = now + DL_PERIOD(t);
        DL_REMAINING(t) = DL_RUNTIME(t);
    } else if (t->policy == SCHED_NORMAL) {
        const size_t penalty = 100000;  // 100us
        CFS_VRUNTIME(t)      = cpu->min_vruntime + penalty;
    } else {
        RT_ARRIVAL(t) = now;
    }

    add_to_runqueue(cpu, t);
    cpu->thread_count++;

    if (cpu->curr_thread && sched_should_preempt(t, cpu->curr_thread)) {
        cpu->reschedule_needed = true;

        if (cpu != smp_current_core()) {
            smp_send_reschedule_ipi(cpu);
        }
    }

    release_interrupt_lock(&cpu->lock);
}

void scheduler_remove_thread(thread_t* t) {
    if (!t) {
        errno = EINVAL;
        KLOG_WARN("SCHED: remove_thread called with null thread\n");
        return;
    }

    per_cpu_data_t* cpu = nullptr;

    while (true) {
        uint32_t expected_cpu = *(volatile uint32_t*)&t->assigned_cpu;

        if (expected_cpu == UINT32_MAX) {
            t->state = THREAD_TERMINATED;
            return;
        }

        cpu = smp_get_core(expected_cpu);
        acquire_interrupt_lock(&cpu->lock);

        if (t->assigned_cpu == expected_cpu) {
            break;
        }

        release_interrupt_lock(&cpu->lock);
        arch_pause();
    }

    bool is_running = (t == cpu->curr_thread);
    bool on_rq      = t->on_rq;

    if (is_running) {
        // Thread is currently running on a cpu. Since we can't simply remove it, hence we mark it
        // as terminated and let the scheduler handle the rest.
        t->state               = THREAD_TERMINATED;
        cpu->reschedule_needed = true;

        if (cpu != smp_current_core()) {
            smp_send_reschedule_ipi(cpu);
        }
    } else if (on_rq) {
        remove_from_runqueue(cpu, t);

        t->on_rq = false;
        t->state = THREAD_TERMINATED;

        if (cpu->thread_count > 0) {
            cpu->thread_count--;
        }
    } else {
        t->state = THREAD_TERMINATED;

        size_t cpu_load = atomic_load_explicit(&cpu->cpu_load, memory_order_relaxed);

        if (cpu_load >= t->avg_load) {
            atomic_fetch_sub_explicit(&cpu->cpu_load, t->avg_load, memory_order_relaxed);
        } else {
            atomic_store_explicit(&cpu->cpu_load, 0, memory_order_relaxed);
        }
    }

    release_interrupt_lock(&cpu->lock);
}

static inline void double_lock_cpu(per_cpu_data_t* cpu1, per_cpu_data_t* cpu2) {
    if (cpu1->cpu_idx < cpu2->cpu_idx) {
        acquire_interrupt_lock(&cpu1->lock);
        acquire_interrupt_lock(&cpu2->lock);
    } else {
        acquire_interrupt_lock(&cpu2->lock);
        acquire_interrupt_lock(&cpu1->lock);
    }
}

static void double_unlock_cpu(per_cpu_data_t* cpu1, per_cpu_data_t* cpu2) {
    if (cpu1->cpu_idx < cpu2->cpu_idx) {
        release_interrupt_lock(&cpu1->lock);
        release_interrupt_lock(&cpu2->lock);
    } else {
        release_interrupt_lock(&cpu2->lock);
        release_interrupt_lock(&cpu1->lock);
    }
}

static void balance_load(void) {
    per_cpu_data_t* this_cpu = smp_current_core();

    per_cpu_data_t* busiest_cpu = nullptr;
    size_t max_load             = 0;

    if (atomic_load_explicit(&this_cpu->cpu_load, memory_order_relaxed) > PELT_MAX_LOAD) {
        return;
    }

    for (uint32_t i = 0; i < cpu_count; ++i) {
        if (i == this_cpu->cpu_idx) {
            continue;
        }

        per_cpu_data_t* remote = smp_get_core(i);
        size_t remote_load     = atomic_load_explicit(&remote->cpu_load, memory_order_relaxed);

        // Skip idle CPUs
        if (remote_load == 0) {
            continue;
        }

        if (remote_load > max_load) {
            max_load    = remote_load;
            busiest_cpu = remote;
        }
    }

// Only migrate if imbalance is >25% to avoid "Bouncing"
#define IMBALANCE_THRESHOLD(local) ((local) + ((local) >> 2))
    size_t curr_load = atomic_load_explicit(&this_cpu->cpu_load, memory_order_relaxed);

    // Only proceed if the busiest CPU is significantly overloaded compared to us.
    if (!busiest_cpu || max_load <= IMBALANCE_THRESHOLD(curr_load)) {
        return;
    }

    double_lock_cpu(this_cpu, busiest_cpu);

    size_t busiest_load = atomic_load_explicit(&busiest_cpu->cpu_load, memory_order_relaxed);

    // The situation might have changed while we waited for locks, so re-verify for safety.
    if (busiest_load <= IMBALANCE_THRESHOLD(curr_load)) {
        double_unlock_cpu(this_cpu, busiest_cpu);
        return;
    }

    // Find a victim thread to steal. We only steal from the CFS tree, preferably the 'Rightmost'
    // node (Highest VRuntime). These threads are usually the furthest in the future hence moving
    // them doesn't hurt our perfomance than compared to moving the "Leftmost" thread.
    struct rb_node* node = rb_last(&busiest_cpu->cfs_tree.rb_root);
    thread_t* victim     = nullptr;

    while (node) {
        thread_t* t = rb_entry(node, thread_t, rb_node);

        // Can this thread run on our CPU?
        bool affinity_ok = (t->affinity_mask & (1ul << this_cpu->cpu_idx));

        // Is it currently running?
        bool is_running = (t->state == THREAD_RUNNING);

        if (affinity_ok && !is_running) {
            victim = t;
            break;
        }

        node = rb_prev(node);
    }

    if (victim) {
        remove_from_runqueue(busiest_cpu, victim);
        busiest_cpu->thread_count--;

        victim->assigned_cpu = this_cpu->cpu_idx;
        victim->on_rq        = true;

        // When moving across CPUs, the vruntime base might be different. So, we normalize vruntime
        // to the new CPU's timeline to prevent unfair switches. Formula: vruntime = (vruntime -
        // old_min_vruntim) + new_min_vruntime
        int64_t vruntime_norm = (int64_t)CFS_VRUNTIME(victim) - (int64_t)busiest_cpu->min_vruntime;

        if (vruntime_norm < 0) {
            vruntime_norm = 0;
        }

        CFS_VRUNTIME(victim) = (size_t)((int64_t)this_cpu->min_vruntime + vruntime_norm);

        add_to_runqueue(this_cpu, victim);
        this_cpu->thread_count++;

        if (CFS_VRUNTIME(victim) < CFS_VRUNTIME(this_cpu->curr_thread)) {
            this_cpu->reschedule_needed = true;
        }

        KLOG_INFO(
            "SCHED: cpu %zu stole thread %zu from cpu %zu\n",
            this_cpu->cpu_idx,
            victim->tid,
            busiest_cpu->cpu_idx
        );
    }

    double_unlock_cpu(this_cpu, busiest_cpu);
#undef IMBALANCE_THRESHOLD
}

static thread_t* pick_next_thread(per_cpu_data_t* cpu) {
    struct rb_node* node = rb_first_cached(&cpu->dl_tree);

    if (node) {
        return rb_entry(node, thread_t, rb_node);
    }

    node = rb_first_cached(&cpu->rt_tree);

    if (node) {
        return rb_entry(node, thread_t, rb_node);
    }

    node = rb_first_cached(&cpu->cfs_tree);

    if (node) {
        return rb_entry(node, thread_t, rb_node);
    }

    // If we are here, we are jobless. Let's try stealing from our neighbors.
    if ((cpu->balance_counter & 63) == 0) {
        release_interrupt_lock(&cpu->lock);

        balance_load();

        acquire_interrupt_lock(&cpu->lock);

        node = rb_first_cached(&cpu->cfs_tree);

        if (node) {
            return rb_entry(node, thread_t, rb_node);
        }
    }

    return cpu->idle_thread;
}

static inline size_t min_vruntime(size_t a, size_t b) {
    return (a < b) ? a : b;
}

static inline size_t max_vruntime(size_t a, size_t b) {
    return (a > b) ? a : b;
}

static void check_nohz_mode(per_cpu_data_t* cpu, thread_t* next) {
    bool can_stop_tick =
        (cpu->thread_count <= 1) && (next->policy != SCHED_RR) && (next->policy != SCHED_DEADLINE);

    if (can_stop_tick && !cpu->is_nohz_active) {
        lapic_timer_stop();
        cpu->is_nohz_active = true;
    } else if (!can_stop_tick & cpu->is_nohz_active) {
        lapic_timer_start(1);
        cpu->is_nohz_active = false;
    }
}

static void update_curr_stats(per_cpu_data_t* cpu, thread_t* curr, size_t now) {
    if (!curr || curr == cpu->idle_thread) {
        return;
    }

    size_t delta = (now > curr->last_start_time) ? (now - curr->last_start_time) : 0;

    update_thread_load(curr);

    if (curr->policy == SCHED_NORMAL) {
        CFS_TOTAL_RUNTIME(curr) += delta;

        size_t wdelta = calculate_weighted_delta(delta, CFS_NICE_IDX(curr));
        CFS_VRUNTIME(curr) += wdelta;

        // Tracks the miniumum vruntime in the system to prevent new tasks from getting an unfair
        // advantage
        size_t v_min         = CFS_VRUNTIME(curr);
        struct rb_node* left = rb_first_cached(&cpu->cfs_tree);

        if (left) {
            thread_t* t = rb_entry(left, thread_t, rb_node);

            if (CFS_VRUNTIME(t) < v_min) {
                v_min = CFS_VRUNTIME(t);
            }
        }

        if (v_min > cpu->min_vruntime) {
            cpu->min_vruntime = v_min;
        }
    } else if (curr->policy == SCHED_DEADLINE) {
        update_dl_entity(curr, delta);
    } else if (curr->policy == SCHED_RR) {
        if (RT_SLICE(curr) <= delta) {
            RT_SLICE(curr)   = RR_QUANTUM_NS;
            RT_ARRIVAL(curr) = now;
        } else {
            RT_SLICE(curr) -= delta;
        }
    }
}

static void update_cpu_load(per_cpu_data_t* cpu, size_t now) {
    if (cpu->last_load_update == 0) {
        cpu->last_load_update = now;
        return;
    }

    int64_t delta_ns = (int64_t)now - (int64_t)cpu->last_load_update;

    if (delta_ns < 0) {
        delta_ns = 0;
    }

    size_t delta_us = (size_t)delta_ns / 1000;

    if (delta_us == 0) {
        return;
    }

    cpu->last_load_update = now;

    bool is_active = (cpu->curr_thread != cpu->idle_thread);
    cpu->period_contrib += delta_us;

    if (cpu->period_contrib >= 1024) {
        size_t periods = cpu->period_contrib >> 10;
        cpu->period_contrib &= (1024 - 1);

        size_t old_load = cpu->cpu_load;
        size_t new_load = decay_cpu_load(old_load, periods);

        if (is_active) {
            size_t decayed_max = decay_cpu_load(LOAD_AVG_MAX, periods);
            new_load += (LOAD_AVG_MAX - decayed_max);
        }

        cpu->cpu_load = new_load;
    }
}

void schedule(void) {
    per_cpu_data_t* cpu = smp_current_core();

    if (!cpu) {
        errno = ENODEV;
        KLOG_ERROR("SCHED: handler called with no CPU context\n");
        return;
    }

    // If we were in NO_HZ mode, receiving this interrupt means a "Wakeup" event happend. We must
    // ensure the tick is running if we have multiple threads now.
    // if (cpu->is_nohz_active && cpu->thread_count > 0) {
    // lapic_timer_start(1);
    // cpu->is_nohz_active = false;
    // }

    if ((++cpu->balance_counter & 0x3ff) == 0) {
        balance_load();
    }

    thread_t* curr = cpu->curr_thread;
    size_t now     = get_time_now();

    if (curr && curr->state != THREAD_TERMINATED) {
        thread_save_fpu(curr);
    }

    acquire_interrupt_lock(&cpu->lock);

    update_cpu_load(cpu, now);
    if (curr && curr != cpu->idle_thread && (curr->state == THREAD_RUNNING)) {
        update_curr_stats(cpu, curr, now);

        if (curr->state == THREAD_RUNNING) {
            curr->state = THREAD_READY;

            add_to_runqueue(cpu, curr);
        } else {
            cpu->thread_count--;
        }
    }

    thread_t* next = pick_next_thread(cpu);

    // Re-enable after IPI is implemented
    // check_nohz_mode(cpu, next);

    if (curr == next) {
        curr->state           = THREAD_RUNNING;
        curr->last_start_time = now;

        if (curr != cpu->idle_thread) {
            remove_from_runqueue(cpu, curr);
        }

        release_interrupt_lock(&cpu->lock);
        return;
    }

    if (next != cpu->idle_thread) {
        remove_from_runqueue(cpu, next);
        next->on_rq = false;
    }

    cpu->curr_thread      = next;
    next->state           = THREAD_RUNNING;
    next->assigned_cpu    = cpu->cpu_idx;
    next->last_start_time = now;

    process_t* next_proc = next->owner;
    process_t* curr_proc = curr ? curr->owner : nullptr;

#ifdef __x86_64__
    update_tss_rsp(&cpu->tss, next->kernel_stack_top);
#endif

    if (next_proc && (curr_proc != next_proc)) {
        write_cr3(next_proc->map.phys_root);
    }

    thread_restore_fpu(next);

    release_interrupt_lock(&cpu->lock);

    arch_switch_context(
        (switch_context_t**)&curr->context_rsp,
        (switch_context_t*)next->context_rsp
    );
}

void scheduler_block(void) {
    per_cpu_data_t* cpu = smp_current_core();

    acquire_interrupt_lock(&cpu->lock);

    thread_t* curr = cpu->curr_thread;
    if (curr && curr != cpu->idle_thread) {
        curr->state            = THREAD_BLOCKED;
        cpu->reschedule_needed = true;
    }

    release_interrupt_lock(&cpu->lock);
    schedule();
}

void scheduler_unblock(thread_t* t) {
    if (!t) {
        return;
    }

    if (t->assigned_cpu == UINT32_MAX) {
        t->assigned_cpu = select_best_cpu(t);
    }

    per_cpu_data_t* cpu = smp_get_core(t->assigned_cpu);

    acquire_interrupt_lock(&cpu->lock);

    if (t->state != THREAD_BLOCKED && t->state != THREAD_SLEEPING) {
        release_interrupt_lock(&cpu->lock);
        return;
    }

    if (t->policy == SCHED_NORMAL) {
        size_t thresh = (MIN_GRANULARITY_NS * 2);
        size_t v_min  = cpu->min_vruntime;

        size_t v_target = (v_min > thresh) ? (v_min - thresh) : 0;

        if (CFS_VRUNTIME(t) < v_target) {
            CFS_VRUNTIME(t) = v_target;
        }
    } else if (t->policy == SCHED_DEADLINE) {
        size_t now = get_time_now();

        if (DL_DEADLINE(t) < now) {
            DL_DEADLINE(t)  = now + DL_PERIOD(t);
            DL_REMAINING(t) = DL_RUNTIME(t);
        }
    }

    t->state = THREAD_READY;
    t->on_rq = true;

    add_to_runqueue(cpu, t);

    cpu->thread_count++;

    if (cpu->curr_thread && sched_should_preempt(t, cpu->curr_thread)) {
        cpu->reschedule_needed = true;

        if (cpu != smp_current_core()) {
            smp_send_reschedule_ipi(cpu);
        }
    }

    release_interrupt_lock(&cpu->lock);
}

void scheduler_sleep(size_t ms) {
    per_cpu_data_t* cpu = smp_current_core();
    thread_t* curr      = cpu->curr_thread;

    if (!curr || curr == cpu->idle_thread) {
        return;
    }

    size_t now           = get_time_now();
    size_t target_wakeup = now + (ms * 1000000);

    acquire_interrupt_lock(&cpu->lock);

    while (true) {
        now = get_time_now();

        if (now >= target_wakeup) {
            break;
        }

        size_t remaining_ns = target_wakeup - now;
        size_t remaining_ms = remaining_ns / 1000000;

        if (remaining_ms == 0) {
            remaining_ms = 1;
        }

        timer_arm_oneshot(
            &cpu->timer_manager,
            &curr->sleep_timer,
            remaining_ms,
            sleep_callback,
            curr
        );

        curr->state            = THREAD_SLEEPING;
        cpu->reschedule_needed = true;

        release_interrupt_lock(&cpu->lock);

        schedule();

        acquire_interrupt_lock(&cpu->lock);
        timer_cancel(&curr->sleep_timer);
    }

    release_interrupt_lock(&cpu->lock);
}

void scheduler_renice(thread_t* t, int nice) {
    if (nice < -20) {
        nice = -20;
    }

    if (nice > 19) {
        nice = 19;
    }

    if (t->policy == SCHED_NORMAL && CFS_NICE(t) == nice) {
        return;
    }

    per_cpu_data_t* cpu = nullptr;

    while (true) {
        uint32_t expected_cpu = *(volatile uint32_t*)&t->assigned_cpu;

        if (expected_cpu == UINT32_MAX) {
            if (t->policy == SCHED_NORMAL) {
                CFS_NICE(t)     = nice;
                CFS_NICE_IDX(t) = nice + 20;
            } else if (t->policy != SCHED_DEADLINE) {
                int new_prio = 50 - nice;

                if (new_prio < 0) {
                    new_prio = 0;
                }

                if (new_prio > 99) {
                    new_prio = 99;
                }

                RT_PRIORITY(t) = new_prio;
            }

            return;
        }

        cpu = smp_get_core(expected_cpu);
        acquire_interrupt_lock(&cpu->lock);

        if (t->assigned_cpu == expected_cpu) {
            break;
        }

        release_interrupt_lock(&cpu->lock);
        arch_pause();
    }

    bool was_on_rq = t->on_rq;

    if (was_on_rq) {
        remove_from_runqueue(cpu, t);
    }

    if (t->policy == SCHED_NORMAL) {
        // Lag = Thread_VRuntime - System_Min_VRuntime
        int64_t vruntime_lag = (int64_t)CFS_VRUNTIME(t) - (int64_t)cpu->min_vruntime;

        // Formula: NewLag = OldLag * (NewInverseWeight / OldInverseWeight)
        uint32_t old_wmult = prio_to_wmult[CFS_NICE_IDX(t)];
        uint32_t new_wmult = prio_to_wmult[nice + 20];

        if (vruntime_lag != 0) {
            vruntime_lag = (int64_t)((uint128_t)vruntime_lag * new_wmult) / old_wmult;
        }

        CFS_VRUNTIME(t) = (size_t)((int64_t)cpu->min_vruntime + vruntime_lag);
        CFS_NICE(t)     = nice;
        CFS_NICE_IDX(t) = nice + 20;
    } else if (t->policy == SCHED_DEADLINE) {
        KLOG_WARN("SCHED: Ignoriing renice on Deadline task TID=%d\n", t->tid);
    } else {
        int new_prio = 50 - nice;

        if (new_prio < 0) {
            new_prio = 0;
        }

        if (new_prio > 99) {
            new_prio = 99;
        }

        RT_PRIORITY(t) = new_prio;
    }

    if (was_on_rq) {
        add_to_runqueue(cpu, t);

        if (cpu->curr_thread && sched_should_preempt(t, cpu->curr_thread)) {
            cpu->reschedule_needed = true;

            if (cpu != smp_current_core()) {
                smp_send_reschedule_ipi(cpu);
            }
        }
    }

    release_interrupt_lock(&cpu->lock);
}

void scheduler_yield(void) {
    per_cpu_data_t* cpu = smp_current_core();

    acquire_interrupt_lock(&cpu->lock);

    thread_t* curr = cpu->curr_thread;

    if (curr && curr != cpu->idle_thread) {
        size_t now = get_time_now();

        if (curr->policy == SCHED_DEADLINE) {
            DL_REMAINING(curr) = DL_RUNTIME(curr);
            DL_DEADLINE(curr) += DL_PERIOD(curr);

            if (DL_DEADLINE(curr) < now) {
                DL_DEADLINE(curr) = now + DL_PERIOD(curr);
            }
        } else if (curr->policy == SCHED_NORMAL) {
            const size_t penalty_ns = 2000000;  // 2ms
            size_t wpenalty         = calculate_weighted_delta(penalty_ns, CFS_NICE_IDX(curr));

            CFS_VRUNTIME(curr) += wpenalty;
        } else {
            RT_ARRIVAL(curr) = now;

            if (curr->policy == SCHED_RR) {
                RT_SLICE(curr) = RR_QUANTUM_NS;
            }
        }

        cpu->reschedule_needed = true;
    }

    release_interrupt_lock(&cpu->lock);
    schedule();
}

bool scheduler_is_initialized(void) {
    return initialized;
}

process_t* get_kernel_process(void) {
    return kernel_proc;
}