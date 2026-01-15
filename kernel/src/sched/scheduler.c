#include "sched/scheduler.h"

#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "arch.h"
#include "boot/boot.h"
#include "compiler.h"
#include "cpu/exception.h"
#include "cpu/gdt.h"
#include "cpu/lapic.h"
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

static process_t* kernel_proc = nullptr;
static bool initialized       = false;

static uint32_t cpu_count = 0;

static size_t cfs_min_granularity = 0;
static size_t yield_penalty       = 0;
static size_t target_latency      = 0;
static size_t RR_QUANTUM          = 0;

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

static void sleep_callback(void* ctx) {
    thread_t* t = (thread_t*)ctx;

    if (t->state != THREAD_SLEEPING) {
        return;
    }

    scheduler_unblock(t);
}

void scheduler_init(void) {
    kernel_proc = process_create(true);
    cpu_count   = (uint32_t)mp_request.response->cpu_count;

    if (!kernel_proc) {
        if (errno == 0) {
            errno = ENOMEM;
        }

        KLOG_ERROR("SCHED: failed to create kernel process errno=%d\n", errno);
        return;
    }

    thread_create_args_t args = {
        .proc   = kernel_proc,
        .entry  = idle_task_entry,
        .arg    = nullptr,
        .policy = SCHED_NORMAL,
        .normal = {.nice = -19},
    };

    for (uint32_t i = 0; i < cpu_count; ++i) {
        per_cpu_data_t* cpu = smp_get_core(i);

        acquire_interrupt_lock(&cpu->lock);

        thread_t* idle = thread_create(&args);

        if (!idle) {
            int err = errno ? errno : EINVAL;
            KLOG_ERROR("SCHED: failed to create idle thread cpu=%u errno=%d\n", i, err);
            release_interrupt_lock(&cpu->lock);
            return;
        }

        cpu->cfs_tree     = RB_ROOT_CACHED;
        cpu->min_vruntime = 0;

        cpu->idle_thread  = idle;
        cpu->curr_thread  = idle;
        cpu->thread_count = 1;

        cpu->balance_counter   = 0;
        cpu->reschedule_needed = false;

        release_interrupt_lock(&cpu->lock);
    }

    const size_t ticks_per_ns = timer_get_hz() / 1000000000ul;

    cfs_min_granularity = ticks_per_ns * 2500000ul;   // 2.5 ms
    yield_penalty       = ticks_per_ns * 5000000ul;   // 5 ms
    target_latency      = ticks_per_ns * 20000000ul;  // 20 ms
    RR_QUANTUM          = ticks_per_ns * 10000000ul;  // 10ms

    timer_configure(TIMER_PERIODIC, IRQ_TIMER, 1);

    initialized = true;

    KLOG_INFO("SCHED: initialized cpus=%u\n", cpu_count);
}

static int cfs_cmp(thread_t* a, thread_t* b) {
    if (a->vruntime < b->vruntime) {
        return -1;
    }

    if (a->vruntime > b->vruntime) {
        return 1;
    }

    return (a->tid < b->tid) ? -1 : 1;
}

static int rt_cmp(thread_t* a, thread_t* b) {
    if (a->priorty > b->priorty) {
        return -1;
    }

    if (a->priorty < b->priorty) {
        return 1;
    }

    return (a->arrival_time < b->arrival_time) ? -1 : 1;
}

static int dl_cmp(thread_t* a, thread_t* b) {
    if (a->dl_deadline < b->dl_deadline) {
        return -1;
    }

    if (a->dl_deadline > b->dl_deadline) {
        return 1;
    }

    return (a->tid < b->tid) ? -1 : 1;
}

static void cfs_insert(per_cpu_data_t* cpu, thread_t* t) {
    struct rb_node** link  = &cpu->cfs_tree.rb_root.rb_node;
    struct rb_node* parent = nullptr;
    bool is_leftmost       = true;

    while (*link) {
        parent          = *link;
        thread_t* entry = rb_entry(parent, thread_t, rb_node);

        if (cfs_cmp(t, entry) < 0) {
            link = &parent->rb_left;
        } else {
            link        = &parent->rb_right;
            is_leftmost = false;
        }
    }

    rb_link_node(&t->rb_node, parent, link);
    rb_insert_color_cached(&t->rb_node, &cpu->cfs_tree, is_leftmost);
}

static void rt_insert(per_cpu_data_t* cpu, thread_t* t) {
    struct rb_node** link  = &cpu->rt_tree.rb_root.rb_node;
    struct rb_node* parent = nullptr;
    bool is_leftmost       = true;

    while (*link) {
        parent          = *link;
        thread_t* entry = rb_entry(parent, thread_t, rb_node);

        if (rt_cmp(t, entry) < 0) {
            link = &parent->rb_left;
        } else {
            link        = &parent->rb_right;
            is_leftmost = false;
        }
    }

    rb_link_node(&t->rb_node, parent, link);
    rb_insert_color_cached(&t->rb_node, &cpu->rt_tree, is_leftmost);
}

static void dl_insert(per_cpu_data_t* cpu, thread_t* t) {
    struct rb_node** link  = &cpu->dl_tree.rb_root.rb_node;
    struct rb_node* parent = nullptr;
    bool is_leftmost       = true;

    while (*link) {
        parent          = *link;
        thread_t* entry = rb_entry(parent, thread_t, rb_node);

        if (dl_cmp(t, entry) < 0) {
            link = &parent->rb_left;
        } else {
            link        = &parent->rb_right;
            is_leftmost = false;
        }
    }

    rb_link_node(&t->rb_node, parent, link);
    rb_insert_color_cached(&t->rb_node, &cpu->dl_tree, is_leftmost);
}

static void update_dl_entity(thread_t* curr, size_t delta) {
    if (curr->dl_remaining > delta) {
        curr->dl_remaining -= delta;
    } else {
        curr->dl_remaining += curr->dl_period;
        curr->dl_remaining = curr->dl_runtime;
    }
}

static void safe_remove_cached(struct rb_root_cached* root, thread_t* t) {
    rb_erase_cached(&t->rb_node, root);
    rb_init_node(&t->rb_node);
}

static thread_t* pick_next_thread(per_cpu_data_t* cpu) {
    struct rb_node* node = rb_first_cached(&cpu->dl_tree);

    if (node) {
        goto found;
    }

    node = rb_first_cached(&cpu->rt_tree);

    if (node) {
        goto found;
    }

    node = rb_first_cached(&cpu->cfs_tree);

    if (node) {
        goto found;
    }

    return nullptr;
found:
    return rb_entry(node, thread_t, rb_node);
}

static inline size_t get_time_now(void) {
    return timer_get_time();
}

void scheduler_add_thread(thread_t* t) {
    if (!t) {
        errno = EINVAL;
        KLOG_WARN("SCHED: add_thread called with null thread\n");
        return;
    }

    if (t->assigned_cpu == UINT32_MAX) {
        uint32_t cpu    = t->tid % cpu_count;
        t->assigned_cpu = cpu;
    }

    per_cpu_data_t* cpu = smp_get_core(t->assigned_cpu);

    t->state = THREAD_READY;

    if (t->nice == 0) {
        t->nice = 0;
    }

    t->nice_idx = t->nice + 20;

    if (t->policy == SCHED_RR) {
        t->time_slice = RR_QUANTUM;
    }

    acquire_interrupt_lock(&cpu->lock);

    size_t now = get_time_now();

    if (t->policy == SCHED_DEADLINE) {
        t->dl_deadline  = now + t->dl_period;
        t->dl_remaining = t->dl_runtime;
        dl_insert(cpu, t);
    } else if (t->policy == SCHED_NORMAL) {
        t->vruntime = cpu->min_vruntime + 100000;
        cfs_insert(cpu, t);
    } else {
        t->arrival_time = now;
        rt_insert(cpu, t);
    }

    cpu->thread_count++;

    if (cpu->curr_thread) {
        bool preempt = false;

        thread_t* curr = cpu->curr_thread;

        // Priority Levels: DL (3) > RT (2) > CFS (1)
        int t_class = 0;
        if (t->policy == SCHED_DEADLINE) {
            t_class = 3;
        } else if (t->policy != SCHED_NORMAL) {
            t_class = 2;
        }

        int curr_class = 1;
        if (curr->policy == SCHED_DEADLINE) {
            curr_class = 3;
        } else if (curr->policy != SCHED_NORMAL) {
            curr_class = 2;
        }

        if (t_class > curr_class) {
            preempt = true;
        } else if (t_class == curr_class) {
            if (t_class == 3) {
                // DL vs DL: Earliest Deadline wins
                if (t->dl_deadline < curr->dl_deadline) {
                    preempt = true;
                }
            } else if (t_class == 2) {
                // RT vs RT: Higher Priority wins
                if (t->priorty > curr->priorty) {
                    preempt = true;
                }
            } else {
                if (t->vruntime < cpu->curr_thread->vruntime) {
                    size_t diff = cpu->curr_thread->vruntime - t->vruntime;

                    if (diff > cfs_min_granularity) {
                        preempt = true;
                    }
                }
            }
        }

        if (preempt) {
            cpu->reschedule_needed = true;
            // TODO: Send IPI to reschedule
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

    bool is_curr = (t == cpu->curr_thread);

    bool on_rq = !RB_EMPTY_NODE(&t->rb_node) && (t->state == THREAD_READY);

    if (is_curr) {
        // Thread is currently running on a cpu. Since we can't simply remove it, hence we mark it
        // as terminated and let the scheduler handle the rest.
        t->state = THREAD_TERMINATED;

        if (cpu != smp_current_core()) {
            // Send IPI
        }
    } else if (on_rq) {
        // Thread is waiting in the run queue
        if (t->policy == SCHED_DEADLINE) {
            safe_remove_cached(&cpu->dl_tree, t);
        } else if (t->policy == SCHED_NORMAL) {
            safe_remove_cached(&cpu->cfs_tree, t);
        } else {
            safe_remove_cached(&cpu->rt_tree, t);
        }
    } else {
        t->state = THREAD_TERMINATED;
    }

    release_interrupt_lock(&cpu->lock);
}

static inline bool is_imbalance_valid(uint32_t my_load, uint32_t victim_load) {
    if (victim_load <= 1) {
        return false;
    }

    return (victim_load - my_load) >= 2;
}

static void balance_load(void) {
    per_cpu_data_t* this_cpu = smp_current_core();
    uint32_t my_load         = this_cpu->thread_count;

    per_cpu_data_t* victim = nullptr;
    uint32_t max_load      = 0;

    for (uint32_t i = 0; i < cpu_count; ++i) {
        if (i == this_cpu->cpu_idx) {
            continue;
        }

        per_cpu_data_t* cpu = smp_get_core(i);
        uint32_t load       = cpu->thread_count;

        if (load > (this_cpu->thread_count + 1) && load > max_load) {
            max_load = load;
            victim   = cpu;
        }
    }

    // Only steal if victim has more than 1 threads
    if (!victim || !is_imbalance_valid(my_load, max_load)) {
        return;
    }

    // Deadlock-free locking
    per_cpu_data_t* first  = (this_cpu->cpu_idx < victim->cpu_idx) ? this_cpu : victim;
    per_cpu_data_t* second = (this_cpu->cpu_idx < victim->cpu_idx) ? victim : this_cpu;

    acquire_interrupt_lock(&first->lock);
    acquire_interrupt_lock(&second->lock);

    // The situation might have changed while we waited for locks, so re-verify for safety.
    if (!is_imbalance_valid(this_cpu->thread_count, victim->thread_count)) {
        release_interrupt_lock(&second->lock);
        release_interrupt_lock(&second->lock);
        return;
    }

    uint32_t curr_diff       = victim->thread_count - this_cpu->thread_count;
    uint32_t threads_to_move = curr_diff / 2;

    if (threads_to_move > 4) {
        threads_to_move = 4;
    }

    uint32_t moved_count = 0;

    struct rb_node* node = rb_last(&victim->cfs_tree.rb_root);

    while (node && moved_count < threads_to_move) {
        thread_t* t = rb_entry(node, thread_t, rb_node);

        node = rb_prev(node);

        if (t->state == THREAD_READY && t->policy == SCHED_NORMAL) {
            safe_remove_cached(&victim->cfs_tree, t);
            victim->thread_count--;

            // We cannot just copy vruntime. Victim's timeline might be totally different from ours.
            // Formula: NewVRuntime = OutMin + (OldVRuntime - VictimMin)
            int64_t lag = (int64_t)t->vruntime - (int64_t)victim->min_vruntime;

            t->vruntime = (size_t)((int64_t)this_cpu->min_vruntime + lag);

            t->assigned_cpu = this_cpu->cpu_idx;
            cfs_insert(this_cpu, t);
            this_cpu->thread_count++;

            moved_count++;

            KLOG_INFO(
                "SCHED: cpu %zu stole thread %zu from cpu %zu\n",
                this_cpu->cpu_idx,
                t->tid,
                victim->cpu_idx
            );
        }
    }

    release_interrupt_lock(&second->lock);
    release_interrupt_lock(&first->lock);
}

static inline size_t min_vruntime(size_t a, size_t b) {
    return (a < b) ? a : b;
}

static inline size_t max_vruntime(size_t a, size_t b) {
    return (a > b) ? a : b;
}

static size_t get_time_slice(per_cpu_data_t* cpu) {
    size_t thread_count = cpu->thread_count;

    if (thread_count == 0) {
        return cfs_min_granularity;
    }

    size_t slice = target_latency / thread_count;

    // If we have too many threads, we extend the latency period rather than thrashing the cpu with
    // tiny time slices.
    if (slice < cfs_min_granularity) {
        slice = cfs_min_granularity;
    }

    return slice;
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

void schedule(void) {
    per_cpu_data_t* cpu = smp_current_core();

    if (!cpu) {
        errno = ENODEV;
        KLOG_ERROR("SCHED: handler called with no CPU context\n");
        return;
    }

    // If we were in NO_HZ mode, receiving this interrupt means a "Wakeup" event happend. We must
    // ensure the tick is running if we have multiple threads now.
    if (cpu->is_nohz_active && cpu->thread_count > 1) {
        lapic_timer_start(1);
        cpu->is_nohz_active = false;
    }

    if ((++cpu->balance_counter & (1024 - 1)) == 0) {
        balance_load();
    }

    thread_t* curr = cpu->curr_thread;
    size_t now     = get_time_now();

    if (curr && curr->state != THREAD_TERMINATED) {
        thread_save_fpu(curr);
    }

    acquire_interrupt_lock(&cpu->lock);

    thread_t* next = nullptr;
    size_t slice   = get_time_slice(cpu);

    if (curr && (curr->state == THREAD_RUNNING)) {
        size_t delta = (now > curr->last_start_time) ? (now - curr->last_start_time) : 0;

        if (delta < slice) {
            release_interrupt_lock(&cpu->lock);
            return;
        }
    }

    if (curr && curr != cpu->idle_thread) {
        size_t delta = now - curr->last_start_time;

        if (now < curr->last_start_time) {
            delta = 0;
        }

        if (curr->policy == SCHED_DEADLINE) {
            update_dl_entity(curr, delta);

            if (curr->state == THREAD_RUNNING) {
                curr->state = THREAD_READY;
            }

            dl_insert(cpu, curr);
        } else if (curr->policy == SCHED_NORMAL) {
            size_t weighted_delta = calculate_weighted_delta(delta, curr->nice_idx);
            curr->total_runtime += delta;

            size_t v_floor            = curr->vruntime;
            struct rb_node* left_node = rb_first_cached(&cpu->cfs_tree);

            if (left_node) {
                thread_t* left = rb_entry(left_node, thread_t, rb_node);
                v_floor        = min_vruntime(v_floor, left->vruntime);
            }

            cpu->min_vruntime = max_vruntime(cpu->min_vruntime, v_floor);

            if (curr->state == THREAD_RUNNING || curr->state == THREAD_READY) {
                curr->state = THREAD_READY;
                cfs_insert(cpu, curr);
            } else {
                cpu->thread_count--;
            }
        } else {
            if (curr->policy == SCHED_RR) {
                if (curr->time_slice <= delta) {
                    curr->time_slice   = RR_QUANTUM;
                    curr->arrival_time = now;
                } else {
                    curr->time_slice -= delta;
                }
            }

            if (curr->state == THREAD_RUNNING || curr->state == THREAD_READY) {
                curr->state = THREAD_READY;
                rt_insert(cpu, curr);
            } else {
                cpu->thread_count--;
            }
        }
    }

    next = pick_next_thread(cpu);

    if (!next) {
        next = cpu->idle_thread;
    }

    check_nohz_mode(cpu, next);

    if (next) {
        if (next->policy == SCHED_DEADLINE) {
            safe_remove_cached(&cpu->dl_tree, next);
        } else if (next->policy == SCHED_NORMAL) {
            safe_remove_cached(&cpu->cfs_tree, next);
        } else {
            safe_remove_cached(&cpu->rt_tree, next);
        }

        prefetch((void*)next->context_rsp, 1, 3);
    }

    if (curr == next) {
        curr->state           = THREAD_RUNNING;
        curr->last_start_time = now;

        release_interrupt_lock(&cpu->lock);
        return;
    }

    cpu->curr_thread      = next;
    next->state           = THREAD_RUNNING;
    next->assigned_cpu    = cpu->cpu_idx;
    next->last_start_time = now;

    process_t* next_proc = next->owner;
    process_t* curr_proc = curr ? curr->owner : nullptr;

    if (next_proc && (curr_proc != next_proc)) {
        write_cr3(next_proc->map.phys_root);
    }

    release_interrupt_lock(&cpu->lock);

#ifdef __x86_64__
    update_tss_rsp0(&cpu->tss, next->kernel_stack_top);
#endif

    thread_restore_fpu(next);

    arch_switch_context(
        (switch_context_t**)&curr->context_rsp,
        (switch_context_t*)next->context_rsp
    );
}

void scheduler_block(void) {
    per_cpu_data_t* cpu = smp_current_core();

    acquire_interrupt_lock(&cpu->lock);

    thread_t* curr = cpu->curr_thread;
    curr->state    = THREAD_BLOCKED;

    release_interrupt_lock(&cpu->lock);
    scheduler_yield();
}

void scheduler_unblock(thread_t* t) {
    per_cpu_data_t* cpu = smp_get_core(t->assigned_cpu);

    acquire_interrupt_lock(&cpu->lock);

    const size_t latency_bonus = (cfs_min_granularity * 10) / 4;
    size_t target_vruntime     = cpu->min_vruntime;

    if (target_vruntime > latency_bonus) {
        target_vruntime -= latency_bonus;
    } else {
        target_vruntime = 0;
    }

    if (t->vruntime < target_vruntime) {
        t->vruntime = target_vruntime;
    }

    if (t->state == THREAD_BLOCKED || t->state == THREAD_SLEEPING) {
        t->state = THREAD_READY;

        cfs_insert(cpu, t);
    }

    release_interrupt_lock(&cpu->lock);
}

void scheduler_sleep(size_t ms) {
    per_cpu_data_t* cpu = smp_current_core();
    thread_t* curr      = cpu->curr_thread;

    acquire_interrupt_lock(&cpu->lock);
    if (curr && curr != cpu->idle_thread) {
        timer_arm_oneshot(&cpu->timer_manager, &curr->sleep_timer, ms, sleep_callback, curr);
        curr->state = THREAD_SLEEPING;
    }

    release_interrupt_lock(&cpu->lock);

    scheduler_yield();
}

void scheduler_renice(thread_t* t, int nice) {
    if (nice < -20) {
        nice = -20;
    }

    if (nice > 19) {
        nice = 19;
    }

    if (*(volatile int*)&t->nice == nice) {
        return;
    }

    per_cpu_data_t* cpu = nullptr;
    size_t flags        = 0;

    while (true) {
        uint32_t expected_cpu = *(volatile uint32_t*)&t->assigned_cpu;
        cpu                   = smp_get_core(expected_cpu);

        acquire_interrupt_lock(&cpu->lock);

        if (t->assigned_cpu == expected_cpu) {
            break;
        }

        release_interrupt_lock(&cpu->lock);
        arch_pause();
    }

    bool on_rq = (t->state == THREAD_READY) && !RB_EMPTY_NODE(&t->rb_node);

    if (t->nice != nice && t->policy == SCHED_NORMAL) {
        if (on_rq) {
            safe_remove_cached(&cpu->cfs_tree, t);
        }

        // Lag = Thread_VRuntime - System_Min_VRuntime
        int64_t vruntime_lag = (int64_t)t->vruntime - (int64_t)cpu->min_vruntime;

        // Formula: NewLag = OldLag * (NewInverseWeight / OldInverseWeight)
        uint32_t old_wmult = prio_to_wmult[t->nice_idx];
        uint32_t new_wmult = prio_to_wmult[nice + 20];

        if (vruntime_lag != 0) {
            vruntime_lag = (int64_t)((uint128_t)vruntime_lag * new_wmult) / old_wmult;
        }

        t->vruntime = (size_t)((int64_t)cpu->min_vruntime + vruntime_lag);
        t->nice     = nice;
        t->nice_idx = nice + 20;

        if (on_rq) {
            cfs_insert(cpu, t);
        }
    }

    if (t->policy != SCHED_NORMAL) {
        t->priorty = -nice + 20;
    }

    release_interrupt_lock(&cpu->lock);
}

void scheduler_yield(void) {
    per_cpu_data_t* cpu = smp_current_core();

    acquire_interrupt_lock(&cpu->lock);

    thread_t* curr = cpu->curr_thread;

    if (curr && curr != cpu->idle_thread) {
        if (curr->policy == SCHED_DEADLINE) {
            curr->dl_deadline  = get_time_now() + curr->dl_period;
            curr->dl_remaining = curr->dl_runtime;
        } else if (curr->policy == SCHED_NORMAL) {
            size_t penalty  = yield_penalty;
            size_t wpenalty = calculate_weighted_delta(penalty, curr->nice_idx);

            curr->vruntime += wpenalty;
        } else {
            // RT tasks are sorted by Priority + Arrival Time. To yield, we simply rest the "Arrival
            // Time" to now. This makes the thread appear newer than others at the same priority,
            // effectively moving it to the back of the line.
            curr->arrival_time = get_time_now();
        }

        curr->state = THREAD_READY;
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