#include <llvm-libc-macros/generic-error-number-macros.h>
#include <stdatomic.h>
#include <stddef.h>
#include <stdint.h>

#include "arch.h"
#include "boot/boot.h"
#include "compiler.h"
#include "core/errors.h"
#include "cpu/exception.h"
#include "cpu/gdt.h"
#include "cpu/smp.h"
#include "drivers/arch_timer.h"
#include "drivers/timer.h"
#include "libs/log.h"
#include "libs/spinlock.h"
#include "memory/vma.h"
#include "memory/vmm.h"
#include "sched/ipc.h"
#include "sched/process.h"
#include "sched/rcu.h"
#include "sched/sched_class.h"
#include "sched/scheduler.h"

#define PELT_MAX_LOAD 1024ul
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

static bool sched_should_preempt(thread_t* new_task, thread_t* curr_task) {
    // If there is no current task or it is alread yielding/blocked, we must preempt to schedule the
    // new task.
    if (unlikely(!curr_task || curr_task->state != THREAD_RUNNING)) return true;

    const struct sched_class* new_class  = new_task->sched_class;
    const struct sched_class* curr_class = curr_task->sched_class;

    // Strict priority dominance (Real-Time > CFS > Idle)
    if (new_class->priority > curr_class->priority) return true;
    if (new_class->priority < curr_class->priority) return false;

    // If they share the same policy, delegate to the specific algorithm
    if (new_task->sched_class->check_preempt)
        return new_task->sched_class->check_preempt(new_task, curr_task);

    // If no hook exists, preempt
    return true;
}

static inline size_t decay_load(size_t load, size_t delta_ms) {
    if (delta_ms == 0) return load;
    if (delta_ms >= 2048) return 0;

    size_t half_lives = delta_ms >> 5;  // same as delta_ms / 32 (2^5)
    size_t remainder  = delta_ms & 31;

    return (load * pelt_decay_factors[remainder]) >> 15 >> half_lives;
}

static inline size_t decay_cpu_load(size_t val, size_t n) {
    if (n == 0) return val;
    if (n >= 32) {
        val >>= (n >> 5);
        n &= 31;
    }

    return (size_t)(((uint128_t)val * runnable_avg_yN_inv[n]) >> 32);
}

static void update_thread_load(thread_t* t) {
    const size_t now      = get_time_now();
    const size_t delta_ms = (now - t->last_load_update) / 1000000;

    if (delta_ms == 0) return;
    t->last_load_update = now;

    const size_t decayed_load = decay_load(t->avg_load, delta_ms);
    const size_t contribution =
        (t->state == THREAD_RUNNING) ? (PELT_MAX_LOAD - decay_load(PELT_MAX_LOAD, delta_ms)) : 0;

    t->avg_load = decayed_load + contribution;
    if (t->avg_load > PELT_MAX_LOAD) t->avg_load = PELT_MAX_LOAD;
}

static void update_cpu_load(per_cpu_data_t* cpu, size_t now) {
    if (unlikely(cpu->last_load_update == 0)) {
        cpu->last_load_update = now;
        return;
    }

    int64_t delta_ns = (int64_t)now - (int64_t)cpu->last_load_update;
    size_t delta_us  = (delta_ns < 0 ? 0 : (size_t)delta_ns) / 1000;
    if (delta_us == 0) return;
    cpu->last_load_update = now;
    cpu->period_contrib   = delta_us;

    if (cpu->period_contrib >= 1024) {
        size_t periods = cpu->period_contrib >> 10;
        cpu->period_contrib &= 1023;

        size_t old_load = cpu->cpu_load;
        size_t new_load = decay_cpu_load(old_load, periods);
        if (cpu->curr_thread != cpu->idle_thread) {
            new_load += (LOAD_AVG_MAX - decay_cpu_load(LOAD_AVG_MAX, periods));
        }

        cpu->cpu_load = new_load;
    }
}

static per_cpu_data_t* lock_thread_cpu(thread_t* t, size_t* flags_out) {
    per_cpu_data_t* cpu;
    while (true) {
        uint32_t expected_cpu =
            atomic_load_explicit((_Atomic uint32_t*)&t->assigned_cpu, memory_order_acquire);
        if (unlikely(expected_cpu == UINT32_MAX)) {
            return nullptr;
        }

        cpu        = smp_get_core(expected_cpu);
        *flags_out = acquire_qinterrupt_lock(&cpu->lock);

        if (likely(t->assigned_cpu == expected_cpu)) {
            return cpu;
        }

        release_qinterrupt_lock(&cpu->lock, *flags_out);
        arch_pause();
    }
}

static inline void switch_mm_and_fpu(per_cpu_data_t* cpu, thread_t* curr, thread_t* next) {
    process_t* next_proc = next->owner;
    process_t* curr_proc = curr ? curr->owner : nullptr;

#ifdef __x86_64__
    update_tss_rsp(&cpu->arch.tss, next->kernel_stack_top);
#endif

    cpu->kstack_top = next->kernel_stack_top;
    if (next_proc && curr_proc != next_proc) pagemap_load(next_proc->vspace->map);

    thread_restore_fpu(next);
    cpu->reschedule_needed = false;
}

static inline void enqueue_and_check_preempt(per_cpu_data_t* cpu, thread_t* t) {
    t->state = THREAD_READY;
    t->sched_class->enqueue_task(cpu, t);
    cpu->thread_count++;

    if (cpu->curr_thread && sched_should_preempt(t, cpu->curr_thread)) {
        cpu->reschedule_needed = true;
        if (cpu != smp_current_core()) smp_send_reschedule_ipi(cpu);
    }
}

static void sleep_callback(void* ctx) {
    scheduler_unblock(ctx);
}

static int internal_sleep_timeout(int64_t timeout_ms, thread_state_t sleep_state) {
    if (unlikely(timeout_ms < 0)) {
        return -EINVAL;
    }

    if (unlikely(timeout_ms == 0)) {
        if (sleep_state == THREAD_SLEEPING) {
            scheduler_yield();
            return 0;
        }

        return ERR_TIMEOUT;
    }

    arch_disable_interrupts();
    per_cpu_data_t* cpu = smp_current_core();
    thread_t* curr      = cpu->curr_thread;

    if (unlikely(!curr || curr == cpu->idle_thread)) {
        arch_enable_interrupts();
        return -EPERM;
    }

    acquire_qspinlock(&cpu->lock);
    curr->state            = sleep_state;
    cpu->reschedule_needed = true;

    lrtimer_arm_oneshot(
        cpu->lrtimer_manager,
        &curr->sleep_timer,
        (uint64_t)timeout_ms,
        sleep_callback,
        curr
    );
    release_qspinlock(&cpu->lock);

    schedule();

    arch_disable_interrupts();
    cpu                = smp_current_core();
    bool woke_up_early = lrtimer_cancel(&curr->sleep_timer);
    arch_enable_interrupts();

    if (woke_up_early) {
        return (sleep_state == THREAD_SLEEPING) ? -EINTR : ERR_TIMEOUT;
    }

    return 0;
}

static void idle_task_entry(void*) {
    while (true) {
        arch_disable_interrupts();
        rcu_idle_enter();

        if (smp_current_core()->reschedule_needed) {
            arch_enable_interrupts();
            schedule();
        } else {
            arch_halt(true);
        }
    }
}

static inline void
double_lock_cpu(per_cpu_data_t* cpu1, per_cpu_data_t* cpu2, size_t* flags1, size_t* flags2) {
    if (cpu1->cpu_idx < cpu2->cpu_idx) {
        *flags1 = acquire_qinterrupt_lock(&cpu1->lock);
        *flags2 = acquire_qinterrupt_lock(&cpu2->lock);
    } else {
        *flags2 = acquire_qinterrupt_lock(&cpu2->lock);
        *flags1 = acquire_qinterrupt_lock(&cpu1->lock);
    }
}

static void
double_unlock_cpu(per_cpu_data_t* cpu1, per_cpu_data_t* cpu2, size_t flags1, size_t flags2) {
    if (cpu1->cpu_idx < cpu2->cpu_idx) {
        release_qinterrupt_lock(&cpu1->lock, flags1);
        release_qinterrupt_lock(&cpu2->lock, flags2);
    } else {
        release_qinterrupt_lock(&cpu2->lock, flags2);
        release_qinterrupt_lock(&cpu1->lock, flags1);
    }
}

static uint32_t select_best_cpu(thread_t* t) {
    per_cpu_data_t* curr_cpu = smp_current_core();
    uint32_t target_cpu      = t->assigned_cpu;

    // Current CPU is idle/low-load and allowed by affinity
    if (curr_cpu->thread_count <= 1 && (t->affinity_mask & (1ul << curr_cpu->cpu_idx)))
        return curr_cpu->cpu_idx;

    per_cpu_data_t* last_cpu = (target_cpu != UINT32_MAX) ? smp_get_core(target_cpu) : nullptr;

    // Previously assigned CPU is entirely idle
    if (last_cpu && (t->affinity_mask & (1ul << target_cpu))) {
        if (last_cpu->thread_count == 0) return target_cpu;

        // Check if all SMT siblings of the last CPU are also idle
        size_t sibs        = cpumask_get(&last_cpu->arch.topology.core_siblings, last_cpu->cpu_idx);
        bool are_sibs_busy = false;

        while (sibs) {
            int idx = ctz(sibs);
            if (smp_get_core((uint32_t)idx)->thread_count > 0) {
                are_sibs_busy = true;
                break;
            }

            // Instantly clear the lowest set bit
            // Learn more:
            // https://softwareengineering.stackexchange.com/questions/304876/explanation-to-why-counting-bits-set-brian-kernighans-way-works
            sibs &= sibs - 1;
        }

        if (!are_sibs_busy) return target_cpu;
    }

    // Calculate cost across all allowed CPUs
    uint32_t best_cpu  = UINT32_MAX;
    size_t min_cost    = SIZE_MAX;
    uint32_t cpu_count = mp_request.response->cpu_count;

    for (uint32_t i = 0; i < cpu_count; ++i) {
        if (!((t->affinity_mask >> i) & 1)) continue;

        per_cpu_data_t* target = smp_get_core(i);

        // Base cost = CPU load + static thread count weight
        size_t curr_cost = atomic_load_explicit(&target->cpu_load, memory_order_relaxed) +
                           ((size_t)target->thread_count * 100);

        // Add SMT sibling cost
        size_t sibs = cpumask_get(&target->arch.topology.core_siblings, i);
        sibs &= ~(1ul << i);

        while (sibs) {
            int idx                 = ctz(sibs);
            per_cpu_data_t* sibling = smp_get_core((uint32_t)idx);

            if (sibling->thread_count > 0)
                curr_cost += COST_SMT_THREAD +
                             (atomic_load_explicit(&sibling->cpu_load, memory_order_relaxed) / 2);

            sibs &= sibs - 1;
        }

        if (last_cpu && i != target_cpu) {
            if (cpumask_get(&target->arch.topology.llc_siblings, target_cpu))
                curr_cost += (MIGRATION_COST_NS / 2000);  // Shares the same L3 cache
            else
                curr_cost += (MIGRATION_COST_NS / 1000);  // Different L3 cache
        }

        if (curr_cost < min_cost) {
            min_cost = curr_cost;
            best_cpu = i;
        }
    }

    if (best_cpu == UINT32_MAX) return last_cpu ? target_cpu : 0;
    return best_cpu;
}

static void balance_load(void) {
    per_cpu_data_t* this_cpu    = smp_current_core();
    per_cpu_data_t* busiest_cpu = nullptr;
    size_t max_threads          = 0;
    uint32_t cpu_count          = mp_request.response->cpu_count;

    // Find the busiest CPU
    for (uint32_t i = 0; i < cpu_count; ++i) {
        if (i == this_cpu->cpu_idx) continue;

        per_cpu_data_t* remote = smp_get_core(i);
        size_t remote_threads  = remote->thread_count;  // Heuristic read

        if (remote_threads > max_threads) {
            max_threads = remote_threads;
            busiest_cpu = remote;
        }
    }

    // Abort if no one is significantly busier than us
    if (!busiest_cpu || max_threads <= (this_cpu->thread_count + 1)) {
        return;
    }

    size_t flags1, flags2;
    double_lock_cpu(this_cpu, busiest_cpu, &flags1, &flags2);

    // Re-verify under lock to prevent race conditions
    if (busiest_cpu->thread_count <= (this_cpu->thread_count + 1)) {
        double_unlock_cpu(this_cpu, busiest_cpu, flags1, flags2);
        return;
    }

    thread_t* victim = nullptr;

    for (struct sched_class* sc = sched_classes_head; sc; sc = sc->next) {
        if (sc->steal_task) {
            victim = sc->steal_task(busiest_cpu, this_cpu);
            if (victim) break;
        }
    }

    if (victim) {
        KLOG_INFO(
            "SCHED: cpu %zu stole KOID %lu from cpu %zu\n",
            this_cpu->cpu_idx,
            victim->kobj.koid,
            busiest_cpu->cpu_idx
        );

        this_cpu->reschedule_needed = true;
    }

    double_unlock_cpu(this_cpu, busiest_cpu, flags1, flags2);
}

static inline thread_t* pick_highest_priority_task(per_cpu_data_t* cpu) {
    for (struct sched_class* sc = sched_classes_head; sc; sc = sc->next) {
        if (sc->pick_next_task) {
            thread_t* next = sc->pick_next_task(cpu);
            if (next) return next;
        }
    }

    return nullptr;
}

static thread_t* pick_next_task(per_cpu_data_t* cpu, size_t* flags) {
    thread_t* next = pick_highest_priority_task(cpu);

    // We found a task locally
    if (likely(next)) return next;

    // No runnable tasks found. Try stealing from neighbors periodically
    if (unlikely(cpu->balance_counter & 63) == 0) {
        release_qinterrupt_lock(&cpu->lock, *flags);
        balance_load();
        *flags = acquire_qinterrupt_lock(&cpu->lock);

        // Re-check our queues in case balance_load succeeded or someone woke up
        next = pick_highest_priority_task(cpu);
        if (next) return next;
    }

    return cpu->idle_thread;
}

void scheduler_init_kernel_process(void) {
    kernel_space->map = vmm_get_kernel_pagemap();
    kernel_proc       = process_create("kernel_proc", true, kernel_space, nullptr);
    if (!kernel_proc) PANIC("SCHED: failed to create kernel process\n");
}

void scheduler_tick(void) {
    rcu_check_callbacks();
    schedule();
}

void scheduler_init_per_cpu(per_cpu_data_t* cpu) {
    cpu->cfs_tree = RB_ROOT_CACHED;
    cpu->dl_tree  = RB_ROOT_CACHED;
    for (int i = 0; i < MAX_RT_PRIO; ++i) {
        dlist_init(&cpu->rt_queues[i]);
    }

    cpu->rt_bitmap[0]    = 0;
    cpu->rt_bitmap[1]    = 0;
    cpu->rt_thread_count = 0;

    cpu->min_vruntime       = 0;
    cpu->balance_counter    = 0;
    cpu->reschedule_needed  = false;
    cpu->next_jiffy_tick_ns = timer_get_time();
    atomic_store_explicit(&cpu->cpu_load, 0, memory_order_relaxed);

    thread_t* idle = thread_create(
        "idle_thread",
        kernel_proc,
        kernel_space,
        SCHED_IDLE,
        (uintptr_t)idle_task_entry,
        0,
        0,
        nullptr
    );
    if (!idle) PANIC("SCHED: failed to create idle thread for cpu=%u\n", cpu->cpu_idx);

    idle->sched_class   = &idle_sched_class;
    idle->state         = THREAD_READY;
    idle->assigned_cpu  = cpu->cpu_idx;
    idle->affinity_mask = (1ul << cpu->cpu_idx);
    idle->on_rq         = false;

    cpu->idle_thread  = idle;
    cpu->curr_thread  = idle;
    cpu->thread_count = 0;

    timer_configure(TIMER_TSC_DEADLINE, IRQ_TIMER);
    timer_start_ms(1);
    KLOG_DEBUG("SCHED: initialzied scheduler on CPU %u\n", cpu->cpu_idx);
}

void scheduler_init(void) {
    sched_class_init();

    sched_class_register(&dl_sched_class);
    sched_class_register(&rt_rr_sched_class);
    sched_class_register(&rt_fifo_sched_class);
    sched_class_register(&cfs_sched_class);
    sched_class_register(&idle_sched_class);

    scheduler_arch_init();
    ipc_init();

    initialized = true;
}

void schedule(void) {
    per_cpu_data_t* cpu = smp_current_core();
    if (unlikely(!cpu)) return;

    if (unlikely((++cpu->balance_counter & 0x3ff) == 0)) balance_load();

    thread_t* curr = cpu->curr_thread;
    size_t now     = get_time_now();

    if (unlikely(curr->preempt_count > 0)) {
        cpu->reschedule_needed = true;
        return;
    }

    if (likely(curr && curr->state != THREAD_TERMINATED)) thread_save_fpu(curr);

    size_t flags = acquire_qinterrupt_lock(&cpu->lock);
    update_cpu_load(cpu, now);

    if (curr && curr != cpu->idle_thread) {
        if (curr->state == THREAD_RUNNING) {
            update_thread_load(curr);
            if (curr->sched_class->task_tick) curr->sched_class->task_tick(cpu, curr, now);
            curr->state = THREAD_READY;
            curr->sched_class->enqueue_task(cpu, curr);
        } else {
            cpu->thread_count--;
        }
    }

    thread_t* next = pick_next_task(cpu, &flags);
    if (curr == next) {
        curr->state           = THREAD_RUNNING;
        curr->last_start_time = now;
        if (curr != cpu->idle_thread) curr->sched_class->dequeue_task(cpu, curr);
        release_qinterrupt_lock(&cpu->lock, flags);
        return;
    }

    if (next != cpu->idle_thread) next->sched_class->dequeue_task(cpu, next);

    cpu->curr_thread      = next;
    next->state           = THREAD_RUNNING;
    next->assigned_cpu    = cpu->cpu_idx;
    next->last_start_time = now;
    switch_mm_and_fpu(cpu, curr, next);

    release_qinterrupt_lock(&cpu->lock, flags);

    arch_switch_context(
        (switch_context_t**)&curr->context_rsp,
        (switch_context_t*)next->context_rsp
    );
}

void scheduler_directed_yield(thread_t* target) {
    if (unlikely(!target)) return;

    arch_disable_interrupts();
    per_cpu_data_t* cpu = smp_current_core();
    thread_t* curr      = cpu->curr_thread;

    if (target->assigned_cpu != cpu->cpu_idx) {
        scheduler_unblock(target);
        scheduler_yield();
        return;
    }

    acquire_qspinlock(&cpu->lock);

    if (unlikely(target->state != THREAD_BLOCKED && target->state != THREAD_SLEEPING)) {
        release_qspinlock(&cpu->lock);
        arch_enable_interrupts();
        return;
    }

    if (likely(curr && curr->state != THREAD_TERMINATED)) thread_save_fpu(curr);
    size_t now = get_time_now();

    if (likely(curr && curr != cpu->idle_thread)) {
        curr->state = THREAD_READY;
        curr->sched_class->enqueue_task(cpu, curr);
    }

    target->state           = THREAD_RUNNING;
    target->last_start_time = now;
    cpu->curr_thread        = target;
    switch_mm_and_fpu(cpu, curr, target);

    release_qspinlock(&cpu->lock);

    arch_switch_context(
        (switch_context_t**)&curr->context_rsp,
        (switch_context_t*)target->context_rsp
    );

    arch_enable_interrupts();
}

void scheduler_add_thread(thread_t* t) {
    if (unlikely(!t)) return;

    t->sched_class = get_sched_class(t->policy);
    if (!t->sched_class) PANIC("SCHED: Unsupported policy\n");

    update_thread_load(t);
    if (t->assigned_cpu == UINT32_MAX) t->assigned_cpu = select_best_cpu(t);

    per_cpu_data_t* cpu = smp_get_core(t->assigned_cpu);
    size_t flags        = acquire_qinterrupt_lock(&cpu->lock);
    enqueue_and_check_preempt(cpu, t);

    release_qinterrupt_lock(&cpu->lock, flags);
}

void scheduler_remove_thread(thread_t* t) {
    if (unlikely(!t)) return;

    size_t flags;
    per_cpu_data_t* cpu = lock_thread_cpu(t, &flags);

    if (unlikely(!cpu)) {
        t->state = THREAD_TERMINATED;
        return;
    }

    if (t == cpu->curr_thread) {
        t->state               = THREAD_TERMINATED;
        cpu->reschedule_needed = true;
        if (cpu != smp_current_core()) smp_send_reschedule_ipi(cpu);
    } else if (t->on_rq) {
        t->sched_class->dequeue_task(cpu, t);
        t->state = THREAD_TERMINATED;
        if (cpu->thread_count > 0) cpu->thread_count--;
    } else {
        t->state = THREAD_TERMINATED;
    }

    release_qinterrupt_lock(&cpu->lock, flags);
}

int scheduler_renice(thread_t* t, int nice) {
    if (unlikely(!t)) return -EINVAL;

    if (nice < -20) nice = -20;
    if (nice > 19) nice = 19;

    if (unlikely(!t->sched_class || !t->sched_class->renice_task)) return -EINVAL;

    size_t flags;
    per_cpu_data_t* cpu = lock_thread_cpu(t, &flags);
    if (unlikely(!cpu)) {
        t->sched_class->renice_task(nullptr, t, nice);
        return 0;
    }

    bool was_on_rq = t->on_rq;

    if (was_on_rq) t->sched_class->dequeue_task(cpu, t);
    t->sched_class->renice_task(cpu, t, nice);
    if (was_on_rq) enqueue_and_check_preempt(cpu, t);

    release_qinterrupt_lock(&cpu->lock, flags);
    return 0;
}

void scheduler_block(void) {
    arch_disable_interrupts();
    per_cpu_data_t* cpu = smp_current_core();
    thread_t* curr      = cpu->curr_thread;

    if (likely(curr && curr != cpu->idle_thread)) {
        curr->state            = THREAD_BLOCKED;
        cpu->reschedule_needed = true;
    }

    schedule();
    arch_enable_interrupts();
}

void scheduler_yield(void) {
    arch_disable_interrupts();
    per_cpu_data_t* cpu = smp_current_core();
    thread_t* curr      = cpu->curr_thread;

    if (likely(curr && curr != cpu->idle_thread)) {
        if (curr->sched_class->yield_task) curr->sched_class->yield_task(cpu, curr);
        cpu->reschedule_needed = true;
    }

    arch_enable_interrupts();
    schedule();
}

void scheduler_unblock(thread_t* t) {
    if (unlikely(!t)) return;

    if (t->assigned_cpu == UINT32_MAX) t->assigned_cpu = select_best_cpu(t);

    per_cpu_data_t* cpu = smp_get_core(t->assigned_cpu);
    size_t flags        = acquire_qinterrupt_lock(&cpu->lock);

    if (unlikely(t->state != THREAD_BLOCKED && t->state != THREAD_SLEEPING)) {
        release_qinterrupt_lock(&cpu->lock, flags);
        return;
    }

    if (t->sched_class->task_unblock) t->sched_class->task_unblock(cpu, t);
    enqueue_and_check_preempt(cpu, t);
    release_qinterrupt_lock(&cpu->lock, flags);
}

int scheduler_block_timeout(int64_t timeout_ms) {
    return internal_sleep_timeout(timeout_ms, THREAD_BLOCKED);
}

int scheduler_sleep(int64_t timeout_ms) {
    return internal_sleep_timeout(timeout_ms, THREAD_SLEEPING);
}

bool scheduler_is_initialized(void) {
    return initialized;
}

process_t* get_kernel_process(void) {
    return kernel_proc;
}

void preempt_disable(void) {
    per_cpu_data_t* cpu = smp_current_core();
    if (likely(cpu && cpu->curr_thread)) cpu->curr_thread->preempt_count++;

    atomic_signal_fence(memory_order_seq_cst);
}

void preempt_enable(void) {
    atomic_signal_fence(memory_order_seq_cst);

    per_cpu_data_t* cpu = smp_current_core();
    if (likely(cpu)) {
        thread_t* curr = cpu->curr_thread;

        if (likely(curr && curr->preempt_count > 0)) {
            curr->preempt_count--;

            if (unlikely(curr->preempt_count == 0 && cpu->reschedule_needed)) {
                cpu->reschedule_needed = false;
                schedule();
            }
        }
    }
}

uint32_t preempt_count(void) {
    per_cpu_data_t* cpu = smp_current_core();
    if (likely(cpu && cpu->curr_thread)) {
        return cpu->curr_thread->preempt_count;
    }

    return 0;
}