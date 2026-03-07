#include <string.h>

#include "boot/boot.h"
#include "sched/rcu.h"
#include "sched/scheduler.h"

#define QSBR_OFFLINE_EPOCH 0

struct qsbr_domain g_qsbr;

static void qsbr_gp_thread(void* arg);

void init_qsbr_domain(struct qsbr_domain* qsd) {
    const uint32_t cpus = mp_request.response->cpu_count;

    qsd->cpu_count = cpus;
    qsd->per_cpu   = kmalloc(sizeof(struct qsbr_cpu_data) * cpus);
    memset(qsd->per_cpu, 0, sizeof(struct qsbr_cpu_data) * cpus);

    atomic_init(&qsd->global_epoch, 1);
    atomic_init(&qsd->gp_active, false);
    atomic_init(&qsd->gp_request, false);
    create_spinlock(&qsd->gp_lock);

    for (uint32_t i = 0; i < cpus; ++i) {
        atomic_init(&qsd->per_cpu[i].local_epoch, QSBR_OFFLINE_EPOCH);
        slist_init(&qsd->per_cpu[i].pending);
    }

    process_t* kernel_proc = get_kernel_process();
    qsd->gp_thread =
        thread_create("qsbr_gp_thread", kernel_proc, SCHED_RR, qsbr_gp_thread, qsd, 99);
    scheduler_add_thread(qsd->gp_thread);
}

void qsbr_online(struct qsbr_domain* qsd) {
    uint32_t cpu  = smp_current_core()->cpu_idx;
    size_t global = atomic_load_explicit(&qsd->global_epoch, memory_order_relaxed);

    atomic_store_explicit(&qsd->per_cpu[cpu].local_epoch, global, memory_order_release);
}

void qsbr_offline(struct qsbr_domain* qsd) {
    uint32_t cpu = smp_current_core()->cpu_idx;

    atomic_store_explicit(&qsd->per_cpu[cpu].local_epoch, QSBR_OFFLINE_EPOCH, memory_order_release);
}

void qsbr_checkpoint(struct qsbr_domain* qsd) {
    uint32_t cpu = smp_current_core()->cpu_idx;
    size_t local = atomic_load_explicit(&qsd->per_cpu[cpu].local_epoch, memory_order_relaxed);

    if (local == QSBR_OFFLINE_EPOCH) {
        return;
    }

    size_t global = atomic_load_explicit(&qsd->global_epoch, memory_order_relaxed);

    if (local != global) {
        atomic_thread_fence(memory_order_release);
        atomic_store_explicit(&qsd->per_cpu[cpu].local_epoch, global, memory_order_relaxed);
    }
}

void call_qsbr(struct qsbr_domain* qsd, struct rcu_head* head, void (*func)(struct rcu_head*)) {
    head->func   = func;
    uint32_t cpu = smp_current_core()->cpu_idx;

    slist_push_atomic(&head->node, &qsd->per_cpu[cpu].pending);

    if (!atomic_load_explicit(&qsd->gp_active, memory_order_relaxed)) {
        atomic_store_explicit(&qsd->gp_request, true, memory_order_relaxed);

        acquire_spinlock(&qsd->gp_lock);
        scheduler_unblock(qsd->gp_thread);
        release_spinlock(&qsd->gp_lock);
    }
}

void synchronize_qsbr(struct qsbr_domain* qsd) {
    acquire_spinlock(&qsd->gp_lock);

    size_t current    = atomic_load_explicit(&qsd->global_epoch, memory_order_relaxed);
    size_t next_epoch = current + 1;
    if (unlikely(next_epoch == QSBR_OFFLINE_EPOCH)) {
        next_epoch = 1;
    }

    atomic_store_explicit(&qsd->global_epoch, next_epoch, memory_order_release);

    for (uint32_t i = 0; i < qsd->cpu_count; ++i) {
        while (true) {
            size_t remote_epoch =
                atomic_load_explicit(&qsd->per_cpu[i].local_epoch, memory_order_acquire);

            if (remote_epoch == QSBR_OFFLINE_EPOCH || remote_epoch == next_epoch) {
                break;
            }

            scheduler_sleep(1);
        }
    }

    release_spinlock(&qsd->gp_lock);
}

static void qsbr_gp_thread(void* arg) {
    struct qsbr_domain* qsd = (struct qsbr_domain*)arg;
    struct slist_head executing_list;

    while (true) {
        acquire_spinlock(&qsd->gp_lock);

        while (!atomic_load_explicit(&qsd->gp_request, memory_order_relaxed)) {
            release_spinlock(&qsd->gp_lock);
            scheduler_block();
            acquire_spinlock(&qsd->gp_lock);
        }

        atomic_store_explicit(&qsd->gp_request, false, memory_order_relaxed);
        atomic_store_explicit(&qsd->gp_active, true, memory_order_relaxed);

        slist_init(&executing_list);

        for (uint32_t i = 0; i < qsd->cpu_count; ++i) {
            struct slist_node* pending = slist_pop_all_atomic(&qsd->per_cpu[i].pending);
            if (pending) {
                struct slist_head temp = {pending};
                slist_splice(&temp, &executing_list);
            }
        }

        release_spinlock(&qsd->gp_lock);

        if (!slist_empty(&executing_list)) {
            synchronize_qsbr(qsd);

            struct slist_node* node;
            while ((node = slist_pop(&executing_list)) != nullptr) {
                struct rcu_head* cb = slist_entry(node, struct rcu_head, node);
                cb->func(cb);
            }
        }

        atomic_store_explicit(&qsd->gp_active, false, memory_order_release);
    }
}