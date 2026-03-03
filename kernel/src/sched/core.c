#include "arch.h"
#include "boot/boot.h"
#include "compiler.h"
#include "cpu/smp.h"
#include "drivers/arch_timer.h"
#include "drivers/timer.h"
#include "libs/log.h"
#include "sched/rcu.h"
#include "sched/sched_class.h"
#include "sched/scheduler.h"

#define PELT_MAX_LOAD 1024
#define LOAD_AVG_MAX  47742

static process_t* kernel_proc = nullptr;
static bool initialized       = false;

extern void arch_switch_context(switch_context_t** prev, switch_context_t* next);

static inline size_t get_time_now() {
    return timer_get_time();
}

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

static inline size_t decay_load(size_t load, size_t delta_ms) {
    if (delta_ms == 0) {
        return load;
    }

    if (delta_ms >= 2048) {
        return 0;
    }

    size_t half_lives = delta_ms / 32;
    size_t remainder  = delta_ms % 32;

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

static void idle_task_entry(void*) {
    while (true) {
        rcu_barrier_all();
        arch_disable_interrupts();

        if (!smp_current_core()->reschedule_needed) {
            qsbr_exit(&g_qsbr);
            arch_halt(true);
            qsbr_enter(&g_qsbr);
        } else {
            arch_enable_interrupts();
        }

        schedule();
    }
}

static uint32_t select_best_cpu(thread_t* t) {
    per_cpu_data_t* curr_cpu = smp_current_core();

    if (curr_cpu->thread_count <= 1 && (t->affinity_mask & (1ul << curr_cpu->cpu_idx))) {
        return curr_cpu->cpu_idx;
    }

    if (t->assigned_cpu != UINT32_MAX && (t->affinity_mask & (1ul << t->assigned_cpu))) {
        per_cpu_data_t* prev = smp_get_core(t->assigned_cpu);

        if (prev->thread_count == 0) {
            return t->assigned_cpu;
        }

        size_t sibs        = cpumask_get(&prev->topology.core_siblings, prev->cpu_idx);
        bool are_sibs_busy = false;

        while (sibs) {
            int idx = ctz(sibs);
            if (smp_get_core((uint32_t)idx)->thread_count > 0) {
                are_sibs_busy = true;
                break;
            }

            sibs &= ~(1ul << idx);
        }

        if (!are_sibs_busy) {
            return t->assigned_cpu;
        }
    }

    uint32_t best_cpu = UINT32_MAX;
    size_t min_cost   = SIZE_MAX;

    for (uint32_t i = 0; i < mp_request.response->cpu_count; ++i) {
        if (!((t->affinity_mask >> i) & 1)) {
            continue;
        }

        per_cpu_data_t* target = smp_get_core(i);
        size_t curr_cost       = 0;

        curr_cost += atomic_load_explicit(&target->cpu_load, memory_order_relaxed);
        curr_cost += ((size_t)target->thread_count * 100);

        size_t sibs = cpumask_get(&target->topology.core_siblings, i);
        while (sibs) {
            int idx                 = __builtin_ctzll(sibs);
            per_cpu_data_t* sibling = smp_get_core((uint32_t)idx);

            if (sibling->thread_count > 0) {
                curr_cost += COST_SMT_THREAD;
                curr_cost += (atomic_load_explicit(&sibling->cpu_load, memory_order_relaxed) / 2);
            }

            sibs &= ~(1ul << idx);
        }

        if (t->assigned_cpu != UINT32_MAX && i != t->assigned_cpu) {
            per_cpu_data_t* last = smp_get_core(t->assigned_cpu);

            if (last && cpumask_test(&target->topology.llc_siblings, t->assigned_cpu)) {
                curr_cost += (MIGRATION_COST_NS / 2000);
            } else {
                curr_cost += (MIGRATION_COST_NS / 1000);
            }
        }

        if (curr_cost < min_cost) {
            min_cost = curr_cost;
            best_cpu = i;
        }
    }

    if (best_cpu == UINT32_MAX) {
        return (t->assigned_cpu != UINT32_MAX) ? t->assigned_cpu : 0;
    }

    return best_cpu;
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

static inline void double_lock_cpu(per_cpu_data_t* cpu1, per_cpu_data_t* cpu2) {
    if (cpu1->cpu_idx < cpu2->cpu_idx) {
        acquire_interrupt_lock(&cpu1->lock);
        acquire_interrupt_lock(&cpu2->lock);
    } else {
        acquire_interrupt_lock(&cpu2->lock);
        acquire_interrupt_lock(&cpu1->lock);
    }
}

static void balance_load(void) {
    per_cpu_data_t* this_cpu    = smp_current_core();
    per_cpu_data_t* busiest_cpu = nullptr;
    size_t max_threads          = 0;

    for (uint32_t i = 0; i < mp_request.response->cpu_count; ++i) {
        if (i == this_cpu->cpu_idx) continue;

        per_cpu_data_t* remote = smp_get_core(i);
        if (remote->thread_count > max_threads) {
            max_threads = remote->thread_count;
            busiest_cpu = remote;
        }
    }

    if (!busiest_cpu || max_threads <= (this_cpu->thread_count + 1)) {
        return;
    }

    double_lock_cpu(this_cpu, busiest_cpu);

    if (busiest_cpu->thread_count <= (this_cpu->thread_count + 1)) {
        double_unlock_cpu(this_cpu, busiest_cpu);
        return;
    }

    struct sched_class* curr_class = sched_classes_head;
    thread_t* victim               = nullptr;

    while (curr_class) {
        if (curr_class->steal_task) {
            victim = curr_class->steal_task(busiest_cpu, this_cpu);

            if (victim) {
                break;
            }
        }

        curr_class = curr_class->next;
    }

    if (victim) {
        KLOG_INFO(
            "SCHED: cpu %zu stole TID %u from cpu %zu\n",
            this_cpu->cpu_idx,
            victim->tid,
            busiest_cpu->cpu_idx
        );

        this_cpu->reschedule_needed = true;
    }

    double_unlock_cpu(this_cpu, busiest_cpu);
}

static bool sched_should_preempt(thread_t* new_task, thread_t* curr_task) {
    if (!curr_task) {
        return true;
    }

    if (curr_task->state != THREAD_RUNNING) {
        return true;
    }

    if (new_task->sched_class->priority > curr_task->sched_class->priority) {
        return true;
    }

    if (new_task->sched_class->priority < curr_task->sched_class->priority) {
        return false;
    }

    if (new_task->sched_class->check_preempt) {
        return new_task->sched_class->check_preempt(new_task, curr_task);
    }

    return true;
}

void scheduler_init(void) {
    sched_class_init();

    sched_class_register(&dl_sched_class);
    sched_class_register(&rt_rr_sched_class);
    sched_class_register(&rt_fifo_sched_class);
    sched_class_register(&cfs_sched_class);
    sched_class_register(&idle_sched_class);

    kernel_proc = process_create(true);

    if (!kernel_proc) {
        PANIC("SCHED: failed to create kernel process\n");
    }

    thread_create_args_t idle_args = {
        .proc   = kernel_proc,
        .entry  = idle_task_entry,
        .arg    = nullptr,
        .policy = SCHED_IDLE,
    };

    for (uint32_t i = 0; i < mp_request.response->cpu_count; ++i) {
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
            PANIC("SCHED: failed to create idle thread for cpu=%u\n", i);
        }

        idle->sched_class   = &idle_sched_class;
        idle->state         = THREAD_READY;
        idle->assigned_cpu  = i;
        idle->affinity_mask = (1ul << i);
        idle->on_rq         = false;

        cpu->idle_thread  = idle;
        cpu->curr_thread  = idle;
        cpu->thread_count = 0;
    }

    rcu_init();
    timer_configure(TIMER_PERIODIC, IRQ_TIMER, 1);

    initialized = true;
    KLOG_DEBUG("SCHED: initialzied scheduler on %u CPUs\n", mp_request.response->cpu_count);
}

void scheduler_add_thread(thread_t* t) {
    if (!t) {
        return;
    }

    t->sched_class = get_sched_class(t->policy);
    if (!t->sched_class) {
        PANIC("SCHED: Unsupported policy assigned to TID %u\n", t->tid);
    }

    update_thread_load(t);

    if (t->assigned_cpu == UINT32_MAX) {
        t->assigned_cpu = select_best_cpu(t);
    }

    per_cpu_data_t* cpu = smp_get_core(t->assigned_cpu);

    acquire_interrupt_lock(&cpu->lock);

    size_t now = get_time_now();

    if (t->sched_class->init_task) {
        t->sched_class->init_task(cpu, t, now);
    }

    t->state = THREAD_READY;
    t->sched_class->enqueue_task(cpu, t);
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
    if (!t) return;

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

    if (t == cpu->curr_thread) {
        t->state               = THREAD_TERMINATED;
        cpu->reschedule_needed = true;

        if (cpu != smp_current_core()) {
            smp_send_reschedule_ipi(cpu);
        }
    } else if (t->on_rq) {
        t->sched_class->dequeue_task(cpu, t);
        t->state = THREAD_TERMINATED;
        if (cpu->thread_count > 0) cpu->thread_count--;
    } else {
        t->state = THREAD_TERMINATED;
    }

    release_interrupt_lock(&cpu->lock);
}

static thread_t* pick_next_task(per_cpu_data_t* cpu) {
    struct sched_class* sc = sched_classes_head;

    while (sc) {
        if (sc->pick_next_task) {
            thread_t* next = sc->pick_next_task(cpu);
            if (next) {
                return next;
            }
        }

        sc = sc->next;
    }

    // No runnable tasks found. Try stealing from neighbors.
    if ((cpu->balance_counter & 63) == 0) {
        release_interrupt_lock(&cpu->lock);
        balance_load();
        acquire_interrupt_lock(&cpu->lock);

        sc = sched_classes_head;
        while (sc) {
            if (sc->pick_next_task) {
                thread_t* next = sc->pick_next_task(cpu);
                if (next) {
                    return next;
                }
            }

            sc = sc->next;
        }
    }

    return cpu->idle_thread;
}

void schedule(void) {
    per_cpu_data_t* cpu = smp_current_core();
    if (!cpu) {
        return;
    }

    if ((++cpu->balance_counter & 0x3ff) == 0) {
        balance_load();
    }

    rcu_check_callbacks();

    thread_t* curr = cpu->curr_thread;
    size_t now     = get_time_now();

    if (curr && curr->state != THREAD_TERMINATED) {
        thread_save_fpu(curr);
    }

    acquire_interrupt_lock(&cpu->lock);
    qsbr_checkpoint(&g_qsbr);

    update_cpu_load(cpu, now);

    if (curr && curr != cpu->idle_thread) {
        if (curr->state == THREAD_RUNNING) {
            update_thread_load(curr);

            if (curr->sched_class->task_tick) {
                curr->sched_class->task_tick(cpu, curr, now);
            }

            curr->state = THREAD_READY;
            curr->sched_class->enqueue_task(cpu, curr);
        } else {
            cpu->thread_count--;
        }
    }

    thread_t* next = pick_next_task(cpu);

    if (curr == next) {
        curr->state           = THREAD_RUNNING;
        curr->last_start_time = now;
        if (curr != cpu->idle_thread) {
            curr->sched_class->dequeue_task(cpu, curr);
        }

        release_interrupt_lock(&cpu->lock);
        return;
    }

    if (next != cpu->idle_thread) {
        next->sched_class->dequeue_task(cpu, next);
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
        pagemap_load(&next_proc->map);
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
    if (!t) return;

    if (t->assigned_cpu == UINT32_MAX) {
        t->assigned_cpu = select_best_cpu(t);
    }

    per_cpu_data_t* cpu = smp_get_core(t->assigned_cpu);

    acquire_interrupt_lock(&cpu->lock);

    if (t->state != THREAD_BLOCKED && t->state != THREAD_SLEEPING) {
        release_interrupt_lock(&cpu->lock);
        return;
    }

    if (t->sched_class->task_unblock) {
        t->sched_class->task_unblock(cpu, t);
    }

    t->state = THREAD_READY;
    t->sched_class->enqueue_task(cpu, t);
    cpu->thread_count++;

    if (cpu->curr_thread && sched_should_preempt(t, cpu->curr_thread)) {
        cpu->reschedule_needed = true;
        if (cpu != smp_current_core()) {
            smp_send_reschedule_ipi(cpu);
        }
    }

    release_interrupt_lock(&cpu->lock);
}

void scheduler_yield(void) {
    per_cpu_data_t* cpu = smp_current_core();
    acquire_interrupt_lock(&cpu->lock);

    thread_t* curr = cpu->curr_thread;
    if (curr && curr != cpu->idle_thread) {
        if (curr->sched_class->yield_task) {
            curr->sched_class->yield_task(cpu, curr);
        }

        cpu->reschedule_needed = true;
    }

    release_interrupt_lock(&cpu->lock);
    schedule();
}

static void sleep_callback(void* ctx) {
    thread_t* t = (thread_t*)ctx;

    if (t && t->state == THREAD_SLEEPING) {
        scheduler_unblock(t);
    }
}

void scheduler_sleep(size_t ms) {
    per_cpu_data_t* cpu = smp_current_core();
    thread_t* curr      = cpu->curr_thread;

    if (!curr || curr == cpu->idle_thread) return;

    size_t now           = get_time_now();
    size_t target_wakeup = now + (ms * 1000000);

    acquire_interrupt_lock(&cpu->lock);

    while (true) {
        now = get_time_now();
        if (now >= target_wakeup) break;

        size_t remaining_ms = (target_wakeup - now) / 1000000;
        if (remaining_ms == 0) remaining_ms = 1;

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
    if (!t) return;

    if (nice < -20) {
        nice = -20;
    }

    if (nice > 19) {
        nice = 19;
    }

    if (!t->sched_class || !t->sched_class->renice_task) {
        return;
    }

    per_cpu_data_t* cpu = nullptr;

    while (true) {
        uint32_t expected_cpu = *(volatile uint32_t*)&t->assigned_cpu;
        if (expected_cpu == UINT32_MAX) {
            t->sched_class->renice_task(nullptr, t, nice);
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
        t->sched_class->dequeue_task(cpu, t);
    }

    t->sched_class->renice_task(cpu, t, nice);

    if (was_on_rq) {
        t->sched_class->enqueue_task(cpu, t);

        if (cpu->curr_thread && sched_should_preempt(t, cpu->curr_thread)) {
            cpu->reschedule_needed = true;

            if (cpu != smp_current_core()) {
                smp_send_reschedule_ipi(cpu);
            }
        }
    }

    release_interrupt_lock(&cpu->lock);
}

bool scheduler_is_initialized(void) {
    return initialized;
}

process_t* get_kernel_process(void) {
    return kernel_proc;
}