#include "sched/rcu.h"

#include <stdatomic.h>
#include <string.h>

#include "arch.h"
#include "boot/boot.h"
#include "cpu/smp.h"
#include "libs/log.h"
#include "libs/spinlock.h"
#include "memory/heap.h"
#include "memory/memory.h"
#include "memory/pagemap.h"
#include "memory/vma.h"
#include "sched/scheduler.h"

struct srcu_domain g_srcu;
struct qsbr_domain g_qsbr;

static struct rcu_callback_batch* srcu_batches;
static struct rcu_callback_batch* qsbr_batches;

static void init_ring_buffers(struct rcu_callback_batch** batch_ptr, uint32_t cpu_count) {
    *batch_ptr = vmalloc(
        &kernel_space,
        sizeof(struct rcu_callback_batch) * cpu_count,
        VMM_FLAG_READ | VMM_FLAG_WRITE,
        CACHE_WRITE_BACK,
        PAGE_SIZE_SMALL
    );

    memset(*batch_ptr, 0, sizeof(struct rcu_callback_batch) * cpu_count);

    for (uint32_t i = 0; i < cpu_count; ++i) {
        create_spinlock(&(*batch_ptr)[i].lock);
        atomic_store(&(*batch_ptr)[i].head, 0);
        atomic_store(&(*batch_ptr)[i].tail, 0);
    }
}

void rcu_init(void) {
    uint32_t cpus = mp_request.response->cpu_count;

    g_srcu.cpu_count = cpus;
    g_srcu.per_cpu   = kmalloc(sizeof(struct srcu_cpu_data) * cpus);
    memset(g_srcu.per_cpu, 0, sizeof(struct srcu_cpu_data) * cpus);
    atomic_store(&g_srcu.idx, 0);
    create_spinlock(&g_srcu.gp_lock);

    g_qsbr.cpu_count = cpus;
    g_qsbr.per_cpu   = kmalloc(sizeof(struct qsbr_cpu_data) * cpus);
    memset(g_qsbr.per_cpu, 0, sizeof(struct qsbr_cpu_data) * cpus);
    atomic_store(&g_qsbr.global_epoch, 1);
    create_spinlock(&g_qsbr.gp_lock);

    init_ring_buffers(&srcu_batches, cpus);
    init_ring_buffers(&qsbr_batches, cpus);

    KLOG_INFO("RCU: Subsystem initialized (SRCU + QSBR) for %u CPUs\n", cpus);
}

static void internal_queue_callback(
    struct rcu_callback_batch* batches,
    struct rcu_head* head,
    void (*func)(struct rcu_head*)
) {
    head->func = func;

    arch_disable_interrupts();

    uint32_t cpu                     = smp_current_core()->cpu_idx;
    struct rcu_callback_batch* batch = &batches[cpu];

    acquire_spinlock(&batch->lock);

    size_t h    = atomic_load(&batch->head);
    size_t t    = atomic_load(&batch->tail);
    size_t next = (h + 1) % RCU_CALLBACK_RING_SIZE;

    if (next == t) {
        KLOG_ERROR("RCU: Ring buffer full on CPU %u. Callback dropped.\n", cpu);
    } else {
        batch->buffer[h] = head;
        atomic_store(&batch->head, next);
    }

    release_spinlock(&batch->lock);
    arch_enable_interrupts();
}

static void internal_drain_batch(struct rcu_callback_batch* batch) {
    acquire_spinlock(&batch->lock);

    size_t h = atomic_load(&batch->head);
    size_t t = atomic_load(&batch->tail);

    while (t != h) {
        struct rcu_head* cb = batch->buffer[t];

        t = (t + 1) % RCU_CALLBACK_RING_SIZE;

        atomic_store(&batch->tail, t);
        release_spinlock(&batch->lock);

        if (cb && cb->func) {
            cb->func(cb);
        }

        acquire_spinlock(&batch->lock);
        h = atomic_load(&batch->head);
    }

    release_spinlock(&batch->lock);
}

int srcu_read_lock(struct srcu_domain* ssp) {
    arch_disable_interrupts();

    int idx = atomic_load_explicit(&ssp->idx, memory_order_consume) & 0x1;

    ssp->per_cpu[smp_current_core()->cpu_idx].lock_count[idx]++;
    atomic_thread_fence(memory_order_acquire);

    arch_enable_interrupts();
    return idx;
}

void srcu_read_unlock(struct srcu_domain* ssp, int idx) {
    arch_disable_interrupts();

    atomic_thread_fence(memory_order_acquire);
    ssp->per_cpu[smp_current_core()->cpu_idx].unlock_count[idx & 0x1]++;

    arch_enable_interrupts();
}

static bool srcu_readers_active(struct srcu_domain* ssp, int idx) {
    uint64_t locks   = 0;
    uint64_t unlocks = 0;

    for (uint32_t i = 0; i < ssp->cpu_count; ++i) {
        locks += ssp->per_cpu[i].lock_count[idx];
        unlocks += ssp->per_cpu[i].unlock_count[idx];
    }

    return locks == unlocks;
}

void synchronize_srcu(struct srcu_domain* ssp) {
    acquire_spinlock(&ssp->gp_lock);

    int idx = atomic_load(&ssp->idx);
    atomic_store_explicit(&ssp->idx, idx + 1, memory_order_release);

    int old_idx = idx & 0x1;

    while (!srcu_readers_active(ssp, old_idx)) {
        release_spinlock(&ssp->gp_lock);
        scheduler_sleep(1);
        acquire_spinlock(&ssp->gp_lock);
    }

    for (uint32_t i = 0; i < ssp->cpu_count; ++i) {
        internal_drain_batch(&srcu_batches[i]);
    }

    release_spinlock(&ssp->gp_lock);
}

void call_srcu(struct rcu_head* head, void (*func)(struct rcu_head*)) {
    internal_queue_callback(srcu_batches, head, func);
}

void qsbr_enter(struct qsbr_domain* qsd) {
    size_t epoch = atomic_load_explicit(&qsd->global_epoch, memory_order_relaxed);

    // Publish: "I am now relying on data from Epoch X"
    atomic_store_explicit(
        &qsd->per_cpu[smp_current_core()->cpu_idx].local_epoch,
        epoch,
        memory_order_release
    );
}

void qsbr_exit(struct qsbr_domain* qsd) {
    // Publish: "I am offline. I hold no reference."
    atomic_store_explicit(
        &qsd->per_cpu[smp_current_core()->cpu_idx].local_epoch,
        RCU_QSBR_OFFLINE_EPOCH,
        memory_order_release
    );
}

void qsbr_checkpoint(struct qsbr_domain* qsd) {
    uint32_t cpu  = smp_current_core()->cpu_idx;
    size_t global = atomic_load_explicit(&qsd->global_epoch, memory_order_relaxed);
    size_t local  = atomic_load_explicit(&qsd->per_cpu[cpu].local_epoch, memory_order_relaxed);

    // Update only if we fell behind
    if (local != global) {
        atomic_store_explicit(&qsd->per_cpu[cpu].local_epoch, global, memory_order_relaxed);
    }
}

void synchronize_qsbr(struct qsbr_domain* qsd) {
    acquire_spinlock(&qsd->gp_lock);

    size_t curr_epoch = atomic_load(&qsd->global_epoch);
    size_t next_epoch = curr_epoch + 1;

    if (next_epoch == RCU_QSBR_OFFLINE_EPOCH) {
        next_epoch = 1;
    }

    atomic_store_explicit(&qsd->global_epoch, next_epoch, memory_order_release);

    // Wait for all CPUs to acknowledge
    while (true) {
        bool all_safe = true;

        for (uint32_t i = 0; i < qsd->cpu_count; ++i) {
            size_t remote_epoch =
                atomic_load_explicit(&qsd->per_cpu[i].local_epoch, memory_order_acquire);

            // A CPU is safe if: (i) It is offline (0); (ii) It has seen the new epoch (next_epoch)
            if (remote_epoch != RCU_QSBR_OFFLINE_EPOCH && remote_epoch != next_epoch) {
                all_safe = false;
                break;
            }
        }

        if (all_safe) {
            break;
        }

        release_spinlock(&qsd->gp_lock);
        scheduler_sleep(1);
        acquire_spinlock(&qsd->gp_lock);
    }

    for (uint32_t i = 0; i < qsd->cpu_count; ++i) {
        internal_drain_batch(&qsbr_batches[i]);
    }

    release_spinlock(&qsd->gp_lock);
}

void call_qsbr(struct rcu_head* head, void (*func)(struct rcu_head*)) {
    internal_queue_callback(qsbr_batches, head, func);
}

static bool is_batch_empty(struct rcu_callback_batch* batch) {
    size_t h = atomic_load_explicit(&batch->head, memory_order_relaxed);
    size_t t = atomic_load_explicit(&batch->tail, memory_order_relaxed);

    return h == t;
}

void rcu_barrier_all(void) {
    bool need_srcu = false;
    bool need_qsbr = false;
    uint32_t cpus  = g_srcu.cpu_count;

    // Scan for pending SRCU work
    for (uint32_t i = 0; i < cpus; ++i) {
        if (!is_batch_empty(&srcu_batches[i])) {
            need_srcu = true;
            break;
        }
    }

    // Scan for pending QSBR work
    for (uint32_t i = 0; i < cpus; ++i) {
        if (!is_batch_empty(&qsbr_batches[i])) {
            need_qsbr = true;
            break;
        }
    }

    if (need_srcu) {
        // This waits for readers -> flips index -> runs callbacks
        synchronize_srcu(&g_srcu);
    }

    if (need_qsbr) {
        // This waits for epochs -> advances epoch -> runs callbacks
        synchronize_qsbr(&g_qsbr);
    }
}