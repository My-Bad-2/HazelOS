#include "sched/scheduler.h"

#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "arch.h"
#include "boot/boot.h"
#include "cpu/exception.h"
#include "cpu/gdt.h"
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

static uint32_t cpu_count     = 0;
static size_t cfs_granularity = 0;
static size_t yield_penalty   = 0;

// misc/scripts/calculate_weight.py
static const size_t prio_to_weight[40] = {
    88818, 71054, 56843, 45475, 36380, 29104, 23283, 18626, 14901, 11921, 9537, 7629, 6104, 4883,
    3906,  3125,  2500,  2000,  1600,  1280,  1024,  819,   655,   524,   419,  336,  268,  215,
    172,   137,   110,   88,    70,    56,    45,    36,    29,    23,    18,   15,
};

void arch_switch_context(switch_context_t** prev, switch_context_t* next);

static void idle_task_entry(void*) {
    arch_halt(true);
}

static bool is_cpu_idle(per_cpu_data_t* cpu) {
    return cpu->curr_thread == cpu->idle_thread;
}

static inline size_t get_weight(int nice) {
    if (nice < -20) {
        nice = -20;
    }

    if (nice > 19) {
        nice = 19;
    }

    // Map [-20, 19] to index [0, 39]
    return prio_to_weight[nice + 20];
}

static inline size_t calculate_weighted_delta(size_t delta, size_t weight) {
    if (weight == get_weight(DEFAULT_NICE)) {
        return delta;
    }

    uint128_t v = (uint128_t)delta;
    v           = (v * get_weight(DEFAULT_NICE)) / weight;

    return (size_t)v;
}

static void sleep_callback(void* ctx) {
    thread_t* t = (thread_t*)ctx;

    if (t->state != THREAD_SLEEPING) {
        return;
    }

    scheduler_unblock(t);
}

static ssize_t scale_vruntime(ssize_t vruntime, size_t old_weight, size_t new_weight) {
    if (old_weight == new_weight) {
        return vruntime;
    }

    uint128_t v = (uint128_t)vruntime;
    v           = (v * old_weight) / new_weight;

    return (ssize_t)v;
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

    for (uint32_t i = 0; i < cpu_count; ++i) {
        per_cpu_data_t* data = smp_get_core(i);

        acquire_interrupt_lock(&data->lock);

        thread_t* idle = thread_create(kernel_proc, idle_task_entry, nullptr);

        if (!idle) {
            int err = errno ? errno : EINVAL;
            KLOG_ERROR("SCHED: failed to create idle thread cpu=%u errno=%d\n", i, err);
            release_interrupt_lock(&data->lock);
            return;
        }

        data->cfs_tree     = RB_ROOT;
        data->cfs_cache    = nullptr;
        data->min_vruntime = 0;

        data->idle_thread  = idle;
        data->curr_thread  = idle;
        data->thread_count = 1;

        data->balance_counter = 0;

        release_interrupt_lock(&data->lock);
    }

    cfs_granularity = (timer_get_hz() / 10);
    yield_penalty   = (timer_get_hz() / 1000) * 5;

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

    if (a->tid < b->tid) {
        return -1;
    }

    if (a->tid > b->tid) {
        return 1;
    }

    return 0;
}

static void cfs_insert_thread(per_cpu_data_t* cpu, thread_t* t) {
    struct rb_node** link  = &cpu->cfs_tree.rb_node;
    struct rb_node* parent = nullptr;

    bool is_leftmost = true;

    while (*link) {
        parent          = *link;
        thread_t* entry = rb_entry(parent, thread_t, rb_node);

        int cmp = cfs_cmp(t, entry);

        if (cmp < 0) {
            link = &parent->rb_left;
        } else {
            link        = &parent->rb_right;
            is_leftmost = false;
        }
    }

    rb_link_node(&t->rb_node, parent, link);
    rb_insert_color(&t->rb_node, &cpu->cfs_tree);

    if (is_leftmost) {
        cpu->cfs_cache = &t->rb_node;
    }
}

static void cfs_remove_thread(per_cpu_data_t* cpu, thread_t* t) {
    if (cpu->cfs_cache == &t->rb_node) {
        cpu->cfs_cache = rb_next(&t->rb_node);
    }

    rb_erase(&t->rb_node, &cpu->cfs_tree);
    RB_CLEAR_NODE(&t->rb_node);
}

static thread_t* cfs_pick_next(per_cpu_data_t* cpu) {
    struct rb_node* left = cpu->cfs_cache;

    if (!left) {
        left = rb_first(&cpu->cfs_tree);
    }

    if (!left) {
        return nullptr;
    }

    return rb_entry(left, thread_t, rb_node);
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

    uint32_t cpu    = t->tid % cpu_count;
    t->assigned_cpu = cpu;

    per_cpu_data_t* data = smp_get_core(cpu);

    acquire_interrupt_lock(&data->lock);

    if (t->nice == 0 && t->weight == 0) {
        t->nice   = 0;
        t->weight = get_weight(0);
    } else {
        t->weight = get_weight(t->nice);
    }

    t->vruntime        = data->min_vruntime;
    t->state           = THREAD_READY;
    t->last_start_time = get_time_now();

    cfs_insert_thread(data, t);
    data->thread_count++;

    release_interrupt_lock(&data->lock);
}

void scheduler_remove_thread(thread_t* t) {
    if (!t) {
        errno = EINVAL;
        KLOG_WARN("SCHED: remove_thread called with null thread\n");
        return;
    }

    per_cpu_data_t* data = smp_get_core(t->assigned_cpu);

    acquire_interrupt_lock(&data->lock);

    if (t->state == THREAD_READY) {
        cfs_remove_thread(data, t);
        data->thread_count--;
    } else if (t->state == THREAD_RUNNING) {
        data->thread_count--;
    }

    t->state = THREAD_TERMINATED;
    timer_cancel(&t->sleep_timer);

    release_interrupt_lock(&data->lock);
}

static void balance_load(void) {
    per_cpu_data_t* me = smp_current_core();

    if (me->thread_count > 1) {
        return;
    }

    per_cpu_data_t* victim = nullptr;
    uint32_t max_load      = 0;

    for (uint32_t i = 0; i < cpu_count; ++i) {
        if (i == me->cpu_idx) {
            continue;
        }

        per_cpu_data_t* cpu = smp_get_core(i);
        uint32_t load       = cpu->thread_count;

        if (load > (me->thread_count + 1) && load > max_load) {
            max_load = load;
            victim   = cpu;
        }
    }

    // Only steal if victim has more than 1 threads
    if (!victim || max_load < 2) {
        return;
    }

    // Deadlock-free locking
    per_cpu_data_t* first  = (me->cpu_idx < victim->cpu_idx) ? me : victim;
    per_cpu_data_t* second = (me->cpu_idx < victim->cpu_idx) ? victim : me;

    acquire_interrupt_lock(&first->lock);
    acquire_interrupt_lock(&second->lock);

    // The right-most node has the highest vruntime (most cpu usage). Moving it allows the victim to
    // focus on the low vruntime tasks.
    struct rb_node* right = rb_last(&victim->cfs_tree);

    while (right) {
        thread_t* t = rb_entry(right, thread_t, rb_node);

        if (t == victim->idle_thread) {
            right = rb_prev(right);
            continue;
        }

        if (t == victim->curr_thread) {
            right = rb_prev(right);
            continue;
        }

        uint64_t now = get_time_now();

        // If the thread ran very recently, moving it kills performance.
        if (now - t->last_start_time < CACHE_HOT_THRESHOLD) {
            right = rb_prev(right);
            continue;
        }

        cfs_remove_thread(victim, t);
        victim->thread_count--;

        ssize_t lag = (ssize_t)t->vruntime - (ssize_t)victim->min_vruntime;
        t->vruntime = me->min_vruntime + (size_t)lag;

        if (t->vruntime < me->min_vruntime) {
            t->vruntime = me->min_vruntime;
        }

        t->assigned_cpu = me->cpu_idx;
        t->state        = THREAD_READY;
        cfs_insert_thread(me, t);
        me->thread_count++;

        KLOG_INFO(
            "SCHED: cpu %zu stole thread %zu from cpu %zu\n",
            me->cpu_idx,
            t->tid,
            victim->cpu_idx
        );

        break;
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

void scheduler_handler(void) {
    per_cpu_data_t* cpu = smp_current_core();

    if (!cpu) {
        errno = ENODEV;
        KLOG_ERROR("SCHED: handler called with no CPU context\n");
        return;
    }

    if (++cpu->balance_counter >= LOAD_BALANCE_INTERVAL) {
        cpu->balance_counter = 0;
        balance_load();
    }

    acquire_interrupt_lock(&cpu->lock);

    thread_t* curr = cpu->curr_thread;
    thread_t* next = nullptr;

    size_t now = get_time_now();

    if (curr && (curr->state == THREAD_RUNNING)) {
        if ((now - curr->last_start_time) < cfs_granularity) {
            release_interrupt_lock(&cpu->lock);
            return;
        }
    }

    if (curr && curr != cpu->idle_thread) {
        size_t delta = now - curr->last_start_time;

        if (now < curr->last_start_time) {
            delta = 0;
        }

        if (delta == 0) {
            delta = 1;
        }

        size_t weighted_delta = calculate_weighted_delta(delta, curr->weight);

        curr->total_runtime += delta;
        curr->vruntime += weighted_delta;

        size_t v_next             = curr->vruntime;
        struct rb_node* left_node = rb_first(&cpu->cfs_tree);

        if (left_node) {
            thread_t* left = rb_entry(left_node, thread_t, rb_node);
            v_next         = min_vruntime(v_next, left->vruntime);
        }

        cpu->min_vruntime = max_vruntime(cpu->min_vruntime, v_next);

        if (curr->state == THREAD_RUNNING || curr->state == THREAD_READY) {
            curr->state = THREAD_READY;
            cfs_insert_thread(cpu, curr);
        } else {
            cpu->thread_count--;
        }
    }

    next = cfs_pick_next(cpu);

    if (next) {
        cfs_remove_thread(cpu, next);
    } else {
        next = cpu->idle_thread;
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
    next->last_start_time = get_time_now();

    if (curr->owner != next->owner) {
        write_cr3(next->owner->map.phys_root);
    }

#ifdef __x86_64__
    update_tss_rsp0(&cpu->tss, next->kernel_stack_top);
#endif

    if (curr->state != THREAD_TERMINATED) {
        thread_save_fpu(curr);
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
    curr->state    = THREAD_BLOCKED;

    release_interrupt_lock(&cpu->lock);
    scheduler_yield();
}

void scheduler_unblock(thread_t* t) {
    per_cpu_data_t* cpu = smp_get_core(t->assigned_cpu);

    acquire_interrupt_lock(&cpu->lock);

    const size_t latency_bonus = (cfs_granularity * 10) / 4;
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

        cfs_insert_thread(cpu, t);
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
    per_cpu_data_t* cpu = smp_get_core(t->assigned_cpu);

    if (nice < -20) {
        nice = -20;
    }

    if (nice > 19) {
        nice = 19;
    }

    acquire_interrupt_lock(&cpu->lock);

    if (t->nice == nice) {
        release_interrupt_lock(&cpu->lock);
        return;
    }

    bool is_waiting = (t->state == THREAD_READY) && !RB_EMPTY_NODE(&t->rb_node);

    if (is_waiting) {
        cfs_remove_thread(cpu, t);
    }

    // It is always possible that vruntime is slightly ahead of min_vruntime due to clamping or load
    // balancing.
    ssize_t vruntime_lag = (ssize_t)t->vruntime - (ssize_t)cpu->min_vruntime;

    size_t old_weight = t->weight;
    size_t new_weight = get_weight(nice);

    if (vruntime_lag != 0) {
        if (vruntime_lag > 0) {
            vruntime_lag = scale_vruntime(vruntime_lag, old_weight, new_weight);
        } else {
            vruntime_lag = -scale_vruntime(-vruntime_lag, old_weight, new_weight);
        }
    }

    t->vruntime = cpu->min_vruntime + (size_t)vruntime_lag;

    t->nice   = nice;
    t->weight = new_weight;

    if (is_waiting) {
        cfs_insert_thread(cpu, t);
    }

    release_interrupt_lock(&cpu->lock);
}

void scheduler_yield(void) {
    per_cpu_data_t* cpu = smp_current_core();

    acquire_interrupt_lock(&cpu->lock);

    thread_t* curr = cpu->curr_thread;

    if (curr && curr != cpu->idle_thread) {
        size_t penalty = yield_penalty;
        penalty        = calculate_weighted_delta(penalty, curr->weight);

        curr->vruntime += penalty;

        curr->state = THREAD_READY;
    }

    release_interrupt_lock(&cpu->lock);
    scheduler_handler();
}

bool scheduler_is_initialized(void) {
    return initialized;
}

process_t* get_kernel_process(void) {
    return kernel_proc;
}