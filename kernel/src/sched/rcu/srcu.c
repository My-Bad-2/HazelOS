#include <stdatomic.h>
#include <string.h>

#include "boot/boot.h"
#include "cpu/smp.h"
#include "libs/slist.h"
#include "libs/spinlock.h"
#include "sched/process.h"
#include "sched/rcu.h"
#include "sched/scheduler.h"

struct srcu_domain g_srcu;

static void srcu_gp_thread(void* arg);

void init_srcu_domain(struct srcu_domain* ssp) {
    const uint32_t cpus = mp_request.response->cpu_count;
    ssp->cpu_count      = cpus;
    ssp->per_cpu        = kmalloc(sizeof(struct srcu_cpu_data) * cpus);
    memset(ssp->per_cpu, 0, sizeof(struct srcu_cpu_data) * cpus);

    atomic_init(&ssp->idx, 0);
    atomic_init(&ssp->gp_active, false);
    atomic_init(&ssp->gp_request, false);
    create_qspinlock(&ssp->gp_lock);

    for (uint32_t i = 0; i < cpus; ++i) slist_init(&ssp->per_cpu[i].pending);

    process_t* kernel_proc = get_kernel_process();
    ssp->gp_thread =
        thread_create("srcu_gp_thread", kernel_proc, SCHED_RR, srcu_gp_thread, ssp, 99);
    scheduler_add_thread(ssp->gp_thread);
}

int srcu_read_lock(struct srcu_domain* ssp) {
    preempt_disable();

    int idx      = atomic_load_explicit(&ssp->idx, memory_order_acquire) & 1;
    uint32_t cpu = smp_current_core()->cpu_idx;
    atomic_fetch_add_explicit(&ssp->per_cpu[cpu].lock_count[idx], 1, memory_order_relaxed);
    preempt_enable();

    atomic_thread_fence(memory_order_seq_cst);
    return idx;
}

void srcu_read_unlock(struct srcu_domain* ssp, int idx) {
    atomic_thread_fence(memory_order_seq_cst);

    preempt_disable();
    uint32_t cpu = smp_current_core()->cpu_idx;
    atomic_fetch_add_explicit(&ssp->per_cpu[cpu].unlock_count[idx & 1], 1, memory_order_relaxed);
    preempt_enable();
}

void call_srcu(struct srcu_domain* ssp, struct rcu_head* head, void (*func)(struct rcu_head*)) {
    head->func = func;

    preempt_disable();
    uint32_t cpu = smp_current_core()->cpu_idx;
    slist_push_atomic(&head->node, &ssp->per_cpu[cpu].pending);
    preempt_enable();

    if (!atomic_load_explicit(&ssp->gp_active, memory_order_relaxed)) {
        atomic_store_explicit(&ssp->gp_request, true, memory_order_relaxed);

        size_t flags = acquire_qinterrupt_lock(&ssp->gp_lock);
        scheduler_unblock(ssp->gp_thread);
        release_qinterrupt_lock(&ssp->gp_lock, flags);
    }
}

static bool srcu_readers_drained(struct srcu_domain* ssp, int idx) {
    uint64_t locks   = 0;
    uint64_t unlocks = 0;

    // Sum up all lock and unlock counters across all CPUs for the given index
    for (uint32_t i = 0; i < ssp->cpu_count; ++i) {
        locks += atomic_load_explicit(&ssp->per_cpu[i].lock_count[idx], memory_order_relaxed);
        unlocks += atomic_load_explicit(&ssp->per_cpu[i].unlock_count[idx], memory_order_relaxed);
    }

    return locks == unlocks;
}

static void srcu_flip_and_wait(struct srcu_domain* ssp) {
    int old_idx = atomic_load_explicit(&ssp->idx, memory_order_relaxed) & 1;
    atomic_store_explicit(&ssp->idx, old_idx ^ 1, memory_order_seq_cst);
    while (!srcu_readers_drained(ssp, old_idx)) scheduler_sleep(1);
}

void synchronize_srcu(struct srcu_domain* ssp) {
    acquire_qspinlock(&ssp->gp_lock);

    srcu_flip_and_wait(ssp);
    srcu_flip_and_wait(ssp);

    release_qspinlock(&ssp->gp_lock);
}

static void srcu_gp_thread(void* arg) {
    struct srcu_domain* ssp = (struct srcu_domain*)arg;
    struct slist_head executing_list;
    thread_t* self = smp_current_core()->curr_thread;

    while (true) {
        size_t flags = acquire_qinterrupt_lock(&ssp->gp_lock);

        while (!atomic_load_explicit(&ssp->gp_request, memory_order_relaxed)) {
            self->state = THREAD_BLOCKED;
            release_qinterrupt_lock(&ssp->gp_lock, flags);
            schedule();
            flags = acquire_qinterrupt_lock(&ssp->gp_lock);
        }

        atomic_store_explicit(&ssp->gp_request, false, memory_order_relaxed);
        atomic_store_explicit(&ssp->gp_active, true, memory_order_relaxed);

        slist_init(&executing_list);
        for (uint32_t i = 0; i < ssp->cpu_count; ++i) {
            struct slist_node* pending = slist_pop_all_atomic(&ssp->per_cpu[i].pending);

            if (pending) {
                struct slist_head temp = {pending};

                // Rever list to process older callbacks first
                slist_reverse(&temp);
                slist_splice(&temp, &executing_list);
            }
        }

        release_qinterrupt_lock(&ssp->gp_lock, flags);

        if (!slist_empty(&executing_list)) {
            synchronize_srcu(ssp);

            struct slist_node* node;
            while ((node = slist_pop(&executing_list)) != nullptr) {
                struct rcu_head* cb = slist_entry(node, struct rcu_head, node);
                cb->func(cb);
            }
        }

        atomic_store_explicit(&ssp->gp_active, false, memory_order_release);
    }
}