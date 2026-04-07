#include "sched/rcu.h"

#include <stdatomic.h>
#include <stdint.h>
#include <string.h>

#include "boot/boot.h"
#include "cpu/smp.h"
#include "libs/log.h"
#include "libs/slist.h"
#include "libs/spinlock.h"
#include "memory/heap.h"
#include "sched/process.h"
#include "sched/scheduler.h"

#define RCU_FANOUT                 64
#define RCU_MAX_CALLBACKS_PER_TICK 100

struct rcu_state {
    struct rcu_node* node_array;
    struct rcu_node* root;
    uint32_t num_nodes;

    _Atomic(uint64_t) gp_seq;            // Currently active GP
    _Atomic(uint64_t) completed_gp_seq;  // Last finished GP
    atomic_bool gp_active;               // Is a GP currently running?
    atomic_bool gp_request;              // Wake-up flag for GP thread

    struct thread* gp_thread;
    qspinlock_t gp_lock;
};

static struct rcu_state rcu_state;
static void rcu_gp_thread(void* arg);

void rcu_init(void) {
    KLOG_INIT_START("Read-Copy-Write");
    uint32_t cpus = mp_request.response->cpu_count;

    atomic_init(&rcu_state.gp_seq, 0);
    atomic_init(&rcu_state.completed_gp_seq, 0);
    atomic_init(&rcu_state.gp_active, false);
    atomic_init(&rcu_state.gp_request, false);
    create_qspinlock(&rcu_state.gp_lock);

    uint32_t num_leaves  = (cpus + RCU_FANOUT - 1) / RCU_FANOUT;
    uint32_t total_nodes = num_leaves + (num_leaves > 1 ? 1 : 0);

    rcu_state.num_nodes  = total_nodes;
    rcu_state.node_array = kmalloc(sizeof(struct rcu_node) * total_nodes);
    memset(rcu_state.node_array, 0, sizeof(struct rcu_node) * total_nodes);

    struct rcu_node* root = &rcu_state.node_array[0];
    rcu_state.root        = root;

    if (num_leaves == 1) {
        // Flat topology: Root node is the only leaf
        create_qspinlock(&root->lock);

        root->group_num    = 0;
        root->level        = 0;
        root->parent       = nullptr;
        root->qs_mask_init = (cpus == 64) ? UINT64_MAX : ((1ul << cpus) - 1);
    } else {
        // Hierarchical topology: Root + Leaves
        create_qspinlock(&root->lock);
        root->level        = 1;
        root->qs_mask_init = (num_leaves == 64) ? UINT64_MAX : (1ul << num_leaves) - 1;
        root->parent       = nullptr;

        for (uint32_t i = 0; i < num_leaves; ++i) {
            struct rcu_node* leaf = &rcu_state.node_array[i + 1];
            create_qspinlock(&leaf->lock);
            leaf->level     = 0;
            leaf->parent    = root;
            leaf->group_num = i;

            if (i == num_leaves - 1 && (cpus % RCU_FANOUT) != 0) {
                leaf->qs_mask_init = (1ul << (cpus % RCU_FANOUT)) - 1;
            } else {
                leaf->qs_mask_init = ~0ul;
            }
        }
    }

    for (uint32_t i = 0; i < cpus; ++i) {
        struct rcu_data* rdp = smp_get_core(i)->rcu;
        uint32_t leaf_idx    = (num_leaves == 1) ? 0 : (1 + (i / RCU_FANOUT));

        rdp->node = &rcu_state.node_array[leaf_idx];
        rdp->mask = 1ul << (i % RCU_FANOUT);

        slist_init(&rdp->pending);
        slist_init(&rdp->waiting);
        slist_init(&rdp->next_waiting);
        slist_init(&rdp->done);

        rdp->waiting_gp_seq = 0;
        rdp->last_qs_seq    = 0;
        rdp->nesting        = 0;
        rdp->qs_pending     = false;
    }

    process_t* kernel_proc = get_kernel_process();
    rcu_state.gp_thread    = thread_create(
        "rcu_gp_thread",
        kernel_proc,
        kernel_space,
        SCHED_RR,
        (uintptr_t)rcu_gp_thread,
        0,
        0,
        nullptr,
        99
    );
    scheduler_add_thread(rcu_state.gp_thread);

    init_srcu_domain(&g_srcu);

    KLOG_INIT_OK();
}

void rcu_read_lock(void) {
    preempt_disable();
    struct rcu_data* rdp = smp_current_core()->rcu;
    rdp->nesting++;
    atomic_signal_fence(memory_order_acquire);
}

void rcu_read_unlock(void) {
    struct rcu_data* rdp = smp_current_core()->rcu;
    atomic_signal_fence(memory_order_release);
    rdp->nesting--;
    preempt_enable();
}

static void rcu_request_gp(void) {
    atomic_store_explicit(&rcu_state.gp_request, true, memory_order_release);
    uint64_t flags = acquire_qinterrupt_lock(&rcu_state.gp_lock);

    if (!atomic_load_explicit(&rcu_state.gp_active, memory_order_acquire))
        scheduler_unblock(rcu_state.gp_thread);

    release_qinterrupt_lock(&rcu_state.gp_lock, flags);
}

void call_rcu(struct rcu_head* head, void (*func)(struct rcu_head*)) {
    head->func           = func;
    struct rcu_data* rdp = smp_current_core()->rcu;

    slist_push_atomic(&head->node, &rdp->pending);
    if (!atomic_load_explicit(&rcu_state.gp_active, memory_order_relaxed)) rcu_request_gp();
}

static bool rcu_report_qs_rnp(uint64_t mask, struct rcu_node* rnp, uint64_t gp_seq) {
    bool accepted = false;
    if (rnp->gp_seq != gp_seq || !(rnp->qs_mask & mask)) return false;

    while (rnp != nullptr) {
        size_t flags = acquire_qinterrupt_lock(&rnp->lock);
        if (rnp->gp_seq != gp_seq || !(rnp->qs_mask & mask)) {
            release_qinterrupt_lock(&rnp->lock, flags);
            return accepted;
        }

        rnp->qs_mask &= ~mask;
        accepted = true;

        if (rnp->qs_mask != 0) {
            release_qinterrupt_lock(&rnp->lock, flags);
            return true;
        }

        mask                    = 1ul << rnp->group_num;
        struct rcu_node* parent = rnp->parent;
        if (!parent) scheduler_unblock(rcu_state.gp_thread);

        release_qinterrupt_lock(&rnp->lock, flags);
        rnp = parent;
    }

    return true;
}

void rcu_check_callbacks(void) {
    struct rcu_data* rdp = smp_current_core()->rcu;
    uint64_t completed   = atomic_load_explicit(&rcu_state.completed_gp_seq, memory_order_acquire);
    uint64_t active      = atomic_load_explicit(&rcu_state.gp_seq, memory_order_acquire);

    if (!slist_empty(&rdp->waiting) && rdp->waiting_gp_seq <= completed) {
        slist_splice(&rdp->waiting, &rdp->done);
        slist_init(&rdp->waiting);
    }

    if (rdp->last_qs_seq != active) {
        rdp->qs_pending  = true;
        rdp->last_qs_seq = active;
    }

    struct slist_node* new_pending = slist_pop_all_atomic(&rdp->pending);
    if (new_pending) {
        struct slist_head temp = {new_pending};
        slist_reverse(&temp);

        if (slist_empty(&rdp->waiting)) {
            slist_splice(&temp, &rdp->waiting);
            rdp->waiting_gp_seq = active + 1;
            rcu_request_gp();
        } else {
            slist_splice(&temp, &rdp->next_waiting);
        }
    }

    if (slist_empty(&rdp->waiting) && !slist_empty(&rdp->next_waiting)) {
        slist_splice(&rdp->next_waiting, &rdp->waiting);
        slist_init(&rdp->next_waiting);
        rdp->waiting_gp_seq = active + 1;
        rcu_request_gp();
    }

    if (rdp->qs_pending && rdp->nesting == 0)
        if (rcu_report_qs_rnp(rdp->mask, rdp->node, active)) rdp->qs_pending = false;

    struct slist_node* node;
    uint32_t count = 0;
    while (count < RCU_MAX_CALLBACKS_PER_TICK && (node = slist_pop(&rdp->done))) {
        struct rcu_head* cb = slist_entry(node, struct rcu_head, node);
        cb->func(cb);
        count++;
    }
}

static void wakeme_after_rcu(struct rcu_head* head) {
    struct sync_rcu_ctx* ctx = container_of(head, struct sync_rcu_ctx, head);
    complete(&ctx->done);
}

void synchronize_rcu(void) {
    struct sync_rcu_ctx ctx;
    init_completion(&ctx.done);

    // Queue the asynchronous callback which will wake us up
    call_rcu(&ctx.head, wakeme_after_rcu);

    // Block the current thread until complete() is called
    wait_for_completion(&ctx.done);
}

static void rcu_gp_thread(void*) {
    thread_t* self = smp_current_core()->curr_thread;

    while (true) {
        size_t flags = acquire_qinterrupt_lock(&rcu_state.gp_lock);

        while (!atomic_load_explicit(&rcu_state.gp_request, memory_order_relaxed)) {
            self->state = THREAD_BLOCKED;
            release_qinterrupt_lock(&rcu_state.gp_lock, flags);
            schedule();
            flags = acquire_qinterrupt_lock(&rcu_state.gp_lock);
        }

        atomic_store_explicit(&rcu_state.gp_request, false, memory_order_relaxed);
        atomic_store_explicit(&rcu_state.gp_active, true, memory_order_release);
        release_qinterrupt_lock(&rcu_state.gp_lock, flags);

        uint64_t seq = atomic_fetch_add_explicit(&rcu_state.gp_seq, 1, memory_order_release) + 1;

        for (uint32_t i = 0; i < rcu_state.num_nodes; ++i) {
            struct rcu_node* rnp = &rcu_state.node_array[i];
            flags                = acquire_qinterrupt_lock(&rcu_state.gp_lock);
            rnp->gp_seq          = seq;
            rnp->qs_mask         = rnp->qs_mask_init;
            release_qinterrupt_lock(&rcu_state.gp_lock, flags);
        }

        // Wait for Tree to drain
        struct rcu_node* root = rcu_state.root;
        while (true) {
            flags = acquire_qinterrupt_lock(&rcu_state.gp_lock);

            if (root->qs_mask == 0) {
                release_qinterrupt_lock(&rcu_state.gp_lock, flags);
                break;
            }

            self->state = THREAD_BLOCKED;
            release_qinterrupt_lock(&rcu_state.gp_lock, flags);

            schedule();
        }

        atomic_store_explicit(&rcu_state.completed_gp_seq, seq, memory_order_release);
        atomic_store_explicit(&rcu_state.gp_active, false, memory_order_release);
    }
}

void rcu_idle_enter(void) {
    struct rcu_data* rdp = smp_current_core()->rcu;

    if (rdp->qs_pending) {
        rdp->qs_pending = false;
        uint64_t active = atomic_load_explicit(&rcu_state.gp_seq, memory_order_acquire);
        rcu_report_qs_rnp(rdp->mask, rdp->node, active);
    }
}