#include "sched/rcu.h"

#include <stdatomic.h>
#include <string.h>

#include "arch.h"
#include "boot/boot.h"
#include "cpu/smp.h"
#include "libs/dlist.h"
#include "libs/log.h"
#include "libs/spinlock.h"
#include "memory/heap.h"
#include "memory/memory.h"
#include "memory/pagemap.h"
#include "memory/vma.h"
#include "sched/scheduler.h"

#define RCU_FANOUT 64

struct srcu_domain g_srcu;
struct qsbr_domain g_qsbr;
static struct rcu_state rcu_state;

static struct rcu_batch* srcu_batches;
static struct rcu_batch* qsbr_batches;

static void rcu_gp_thread(void*);

static void init_ring_buffers(struct rcu_batch** batch_ptr, uint32_t cpu_count) {
    *batch_ptr = vmalloc(
        &kernel_space,
        sizeof(struct rcu_batch) * cpu_count,
        VMM_FLAG_READ | VMM_FLAG_WRITE,
        CACHE_WRITE_BACK,
        PAGE_SIZE_SMALL
    );

    memset(*batch_ptr, 0, sizeof(struct rcu_batch) * cpu_count);

    for (uint32_t i = 0; i < cpu_count; ++i) {
        create_spinlock(&(*batch_ptr)[i].lock);
        atomic_store(&(*batch_ptr)[i].head, 0);
        atomic_store(&(*batch_ptr)[i].tail, 0);
    }
}

void rcu_init(void) {
    uint32_t cpus = mp_request.response->cpu_count;

    atomic_store(&rcu_state.gp_seq, 0);
    rcu_state.gp_request = false;
    create_spinlock(&rcu_state.gp_lock);

    uint32_t num_leaves  = (cpus + RCU_FANOUT - 1) / RCU_FANOUT;
    uint32_t total_nodes = num_leaves;

    if (num_leaves > 1) {
        total_nodes += 1;
    }

    rcu_state.num_nodes = total_nodes;
    rcu_state.node      = kmalloc(sizeof(struct rcu_node) * total_nodes);
    memset(rcu_state.node, 0, sizeof(struct rcu_node) * total_nodes);

    struct rcu_node* root       = &rcu_state.node[0];
    struct rcu_node* first_leaf = nullptr;

    if (num_leaves == 1) {
        // Single Node case
        create_spinlock(&root->lock);
        root->group_num    = 0;
        root->level        = 0;
        root->parent       = nullptr;
        root->qs_mask_init = (1ul << cpus) - 1;
        first_leaf         = root;
        rcu_state.root     = root;
    } else {
        create_spinlock(&rcu_state.node->lock);
        root->level        = 1;
        root->qs_mask_init = (1ul << num_leaves) - 1;
        root->parent       = nullptr;
        rcu_state.root     = root;

        first_leaf = &rcu_state.node[1];

        for (uint32_t i = 0; i < num_leaves; ++i) {
            struct rcu_node* leaf = &rcu_state.node[i + 1];
            leaf->level           = 0;
            leaf->parent          = root;
            leaf->group_num       = i;

            leaf->qs_mask_init = ~0ul;

            if (i == num_leaves - 1) {
                uint32_t remainder = cpus % RCU_FANOUT;

                if (remainder != 0) {
                    leaf->qs_mask_init = (1ul << remainder) - 1;
                }
            }
        }
    }

    for (uint32_t i = 0; i < cpus; ++i) {
        struct rcu_data* rdp = smp_get_core(i)->rcu;

        uint32_t leaf_idx = i / RCU_FANOUT;

        if (num_leaves == 1) {
            leaf_idx = 0;
        } else {
            leaf_idx += 1;
        }

        rdp->node = &rcu_state.node[leaf_idx];
        rdp->mask = 1ul << (i % RCU_FANOUT);

        memset(&rdp->batch, 0, sizeof(struct rcu_batch));
        create_spinlock(&rdp->batch.lock);
        atomic_store(&rdp->batch.head, 0);
        atomic_store(&rdp->batch.tail, 0);
        atomic_store(&rdp->batch.snapshot, 0);
        atomic_store(&rdp->batch.safe_limit, 0);

        rdp->gq_sq      = 0;
        rdp->qs_pending = false;
    }

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

    thread_create_args_t args = {
        .proc   = get_kernel_process(),
        .entry  = rcu_gp_thread,
        .arg    = nullptr,
        .policy = SCHED_RR,
        .rt     = {.priority = 99}
    };

    thread_t* gp_thread = thread_create(&args);
    rcu_state.gp_thread = gp_thread;

    scheduler_add_thread(gp_thread);

    KLOG_INFO("RCU: Subsystem initialized (Classic + SRCU + QSBR) for %u CPUs\n", cpus);
}

void init_completion(struct completion* x) {
    x->done = 0;
    create_spinlock(&x->lock);
    dlist_init(&x->wait);
}

static void internal_queue_callback(
    struct rcu_batch* batches,
    struct rcu_head* head,
    void (*func)(struct rcu_head*)
) {
    head->func = func;

    arch_disable_interrupts();

    uint32_t cpu            = smp_current_core()->cpu_idx;
    struct rcu_batch* batch = &batches[cpu];

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

static void internal_drain_batch(struct rcu_batch* batch) {
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

static bool is_batch_empty(struct rcu_batch* batch) {
    size_t h = atomic_load_explicit(&batch->head, memory_order_relaxed);
    size_t t = atomic_load_explicit(&batch->tail, memory_order_relaxed);

    return h == t;
}

static void rcu_report_qs_rnp(uint64_t mask, struct rcu_node* rnp, uint64_t gp_seq) {
    struct rcu_node* parent = nullptr;

    while (rnp != nullptr) {
        acquire_spinlock(&rnp->lock);

        if (rnp->grace_period_seq != gp_seq) {
            release_spinlock(&rnp->lock);
            return;
        }

        if (!(rnp->qs_mask & mask)) {
            release_spinlock(&rnp->lock);
            return;
        }

        rnp->qs_mask &= ~mask;

        if (rnp->qs_mask != 0) {
            release_spinlock(&rnp->lock);
            return;
        }

        // All children reported! We must now report to our parent;
        mask   = 1ul << rnp->group_num;
        parent = rnp->parent;

        release_spinlock(&rnp->lock);
        rnp = parent;
    }
}

static void rcu_report_qs_rdp(struct rcu_data* rdp) {
    rdp->qs_pending = false;
    uint64_t gp_seq = rcu_state.gp_seq;

    rcu_report_qs_rnp(rdp->mask, rdp->node, gp_seq);
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

void call_rcu(struct rcu_head* head, void (*func)(struct rcu_head*)) {
    struct rcu_data* rdp    = smp_current_core()->rcu;
    struct rcu_batch* batch = &rdp->batch;

    head->func = func;

    arch_disable_interrupts();
    acquire_spinlock(&batch->lock);

    size_t h    = atomic_load_explicit(&batch->head, memory_order_relaxed);
    size_t next = (h + 1) % RCU_CALLBACK_RING_SIZE;
    size_t t    = atomic_load_explicit(&batch->tail, memory_order_relaxed);

    if (next == t) {
        PANIC("RCU: Callback buffer overflow on CPU %u!", smp_current_core()->cpu_idx);
    }

    batch->buffer[h] = head;
    atomic_store_explicit(&batch->head, next, memory_order_release);

    release_spinlock(&batch->lock);

    // Wake up GP thread if needed
    if (!rcu_state.gp_request) {
        acquire_spinlock(&rcu_state.gp_lock);

        if (!rcu_state.gp_request) {
            rcu_state.gp_request = true;

            if (rcu_state.gp_thread) {
                scheduler_unblock(rcu_state.gp_thread);
            }
        }

        release_spinlock(&rcu_state.gp_lock);
    }

    arch_enable_interrupts();
}

void rcu_check_callbacks(void) {
    struct rcu_data* rdp = smp_current_core()->rcu;

    if (rdp->qs_pending && rdp->nesting == 0) {
        rcu_report_qs_rdp(rdp);
    }

    struct rcu_batch* batch = &rdp->batch;
    size_t limit            = atomic_load_explicit(&batch->safe_limit, memory_order_acquire);
    size_t t                = atomic_load_explicit(&batch->tail, memory_order_relaxed);

    while (t != limit) {
        struct rcu_head* callback = batch->buffer[t];
        t                         = (t + 1) % RCU_CALLBACK_RING_SIZE;
        atomic_store_explicit(&batch->tail, t, memory_order_relaxed);

        if (callback && callback->func) {
            callback->func(callback);
        }
    }
}

static void rcu_gp_thread(void*) {
    uint32_t cpu_count = mp_request.response->cpu_count;

    while (true) {
        acquire_spinlock(&rcu_state.gp_lock);

        while (!rcu_state.gp_request) {
            thread_t* curr = smp_current_core()->curr_thread;

            arch_disable_interrupts();
            curr->state = THREAD_BLOCKED;
            release_spinlock(&rcu_state.gp_lock);
            arch_enable_interrupts();

            schedule();

            acquire_spinlock(&rcu_state.gp_lock);
        }

        rcu_state.gp_request = false;
        release_spinlock(&rcu_state.gp_lock);

        atomic_fetch_add(&rcu_state.gp_seq, 1);
        uint64_t current_gp = atomic_load(&rcu_state.gp_seq);

        for (uint32_t i = 0; i < rcu_state.num_nodes; ++i) {
            struct rcu_node* rnp = &rcu_state.node[i];

            acquire_spinlock(&rnp->lock);
            rnp->qs_mask          = rnp->qs_mask_init;  // Reset mask
            rnp->grace_period_seq = current_gp;         // Update sequence

            release_spinlock(&rnp->lock);
        }

        // Snapshot per-cpu heads
        for (uint32_t i = 0; i < cpu_count; ++i) {
            struct rcu_data* rdp = smp_get_core(i)->rcu;
            size_t head          = atomic_load_explicit(&rdp->batch.head, memory_order_acquire);
            atomic_store(&rdp->batch.snapshot, head);
            rdp->qs_pending = true;
        }

        // Wait for root to be clear
        struct rcu_node* root = rcu_state.root;
        while (true) {
            acquire_spinlock(&root->lock);
            uint64_t mask = root->qs_mask;
            release_spinlock(&root->lock);

            if (mask == 0) {
                break;
            }

            scheduler_sleep(10);
        }

        // Publish
        for (uint32_t i = 0; i < cpu_count; ++i) {
            struct rcu_data* rdp = smp_get_core(i)->rcu;
            size_t snap          = atomic_load(&rdp->batch.snapshot);
            atomic_store_explicit(&rdp->batch.safe_limit, snap, memory_order_release);
        }
    }
}

void rcu_read_lock(void) {
    arch_disable_interrupts();

    struct rcu_data* rdp = smp_current_core()->rcu;

    atomic_signal_fence(memory_order_acquire);

    rdp->nesting++;

    atomic_signal_fence(memory_order_release);
}

void rcu_read_unlock(void) {
    struct rcu_data* rdp = smp_current_core()->rcu;

    atomic_signal_fence(memory_order_acquire);

    rdp->nesting--;

    // If we are the outermost unlock (nesting == 0) and the system was waiting for this CPU to
    // finish, report now.
    if (rdp->nesting == 0) {
        if (rdp->qs_pending) {
            rcu_report_qs_rdp(rdp);
        }
    }

    atomic_signal_fence(memory_order_release);
    arch_enable_interrupts();
}

void complete(struct completion* x) {
    arch_disable_interrupts();
    acquire_spinlock(&x->lock);

    x->done++;

    if (!dlist_empty(&x->wait)) {
        struct dlist_head* first    = x->wait.next;
        struct completion_waiter* w = dlist_entry(first, struct completion_waiter, list);
        scheduler_unblock(w->task);
    }

    release_spinlock(&x->lock);
}

void wait_for_completion(struct completion* x) {
    struct completion_waiter w;
    thread_t* curr = smp_current_core()->curr_thread;

    w.task = curr;
    dlist_init(&w.list);

    acquire_spinlock(&x->lock);

    if (x->done > 0) {
        x->done--;
        release_spinlock(&x->lock);
        return;
    }

    dlist_add_tail(&w.list, &x->wait);

    while (true) {
        curr->state = THREAD_BLOCKED;
        release_spinlock(&x->lock);
        schedule();

        acquire_spinlock(&x->lock);

        if (x->done > 0) {
            x->done--;
            break;
        }
    }

    dlist_del(&w.list);

    release_spinlock(&x->lock);
}

struct sync_rcu_ctx {
    struct rcu_head head;
    struct completion done;
};

static void wakeme_after_rcu(struct rcu_head* head) {
    struct sync_rcu_ctx* ctx = (struct sync_rcu_ctx*)head;
    complete(&ctx->done);
}

void synchronize_rcu(void) {
    struct sync_rcu_ctx ctx;
    init_completion(&ctx.done);

    call_rcu(&ctx.head, wakeme_after_rcu);
    wait_for_completion(&ctx.done);
}