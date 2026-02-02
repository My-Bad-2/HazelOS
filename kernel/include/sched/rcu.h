#include "libs/dlist.h"
#ifndef KERNEL_SCHED_RCU_H
#define KERNEL_SCHED_RCU_H 1

#include <stdatomic.h>
#include <stddef.h>
#include <stdint.h>

#include "libs/spinlock.h"
#include "sched/process.h"

#ifdef __cplusplus
extern "C" {
#endif

#define RCU_CALLBACK_RING_SIZE 4096
#define RCU_QSBR_OFFLINE_EPOCH 0

struct rcu_head {
    void (*func)(struct rcu_head*);
};

struct rcu_batch {
    struct rcu_head* buffer[RCU_CALLBACK_RING_SIZE];
    atomic_size_t head;
    atomic_size_t tail;

    atomic_size_t snapshot;    // Captured 'head' at start of GP
    atomic_size_t safe_limit;  // Safe 'head' at the end of GP

    spinlock_t lock;
};

struct rcu_node {
    spinlock_t lock;
    uint64_t qs_mask;           // Bitmask of CPUs pending QS
    uint64_t qs_mask_init;      // Bitmask of CPUs online for this node
    uint64_t grace_period_seq;  // Current GP sequence number

    struct rcu_node* parent;
    uint8_t group_num;  // bit index in the parent's qsmask
    uint8_t level;      // 0 = Leaf, N = Root
};

struct rcu_data {
    struct rcu_batch batch;
    struct rcu_node* node;  // The leaf node this CPU belongs too

    uint64_t mask;  // Bitmask for this CPU in the leaf node

    bool qs_pending;   // Does the core need to report a QS?
    uint64_t nesting;  // Depth of read-side CS
    uint64_t gq_sq;    // Last GP sequence seen
};

struct rcu_state {
    struct rcu_node* node;
    struct rcu_node* root;

    uint32_t num_nodes;

    atomic_size_t gp_seq;
    bool gp_request;
    thread_t* gp_thread;
    spinlock_t gp_lock;
};

struct srcu_domain {
    atomic_size_t idx;
    atomic_size_t gp_seq;
    spinlock_t gp_lock;

    struct srcu_cpu_data {
        uint64_t lock_count[2];
        uint64_t unlock_count[2];
    }* per_cpu;

    uint32_t cpu_count;
};

struct qsbr_domain {
    atomic_size_t global_epoch;
    spinlock_t gp_lock;

    struct qsbr_cpu_data {
        atomic_size_t local_epoch;
    }* per_cpu;

    uint32_t cpu_count;
};

struct completion {
    uint32_t done;
    spinlock_t lock;
    struct dlist_head wait;
};

struct completion_waiter {
    struct dlist_head list;
    thread_t* task;
};

extern struct srcu_domain g_srcu;
extern struct qsbr_domain g_qsbr;

void rcu_init(void);

void call_rcu(struct rcu_head* head, void (*func)(struct rcu_head*));
void rcu_check_callbacks(void);
void rcu_read_lock(void);
void rcu_read_unlock(void);
void synchronize_rcu(void);

int srcu_read_lock(struct srcu_domain* ssp);
void srcu_read_unlock(struct srcu_domain* ssp, int idx);
void synchronize_srcu(struct srcu_domain* ssp);
void call_srcu(struct rcu_head* head, void (*func)(struct rcu_head*));

void qsbr_enter(struct qsbr_domain* qsd);
void qsbr_exit(struct qsbr_domain* qsd);
void qsbr_checkpoint(struct qsbr_domain* qsd);
void synchronize_qsbr(struct qsbr_domain* qsd);
void call_qsbr(struct rcu_head* head, void (*func)(struct rcu_head*));

void rcu_barrier_all(void);

void init_completion(struct completion* x);
void wait_for_completion(struct completion* x);
void complete(struct completion* x);

#ifdef __cplusplus
}
#endif

#endif