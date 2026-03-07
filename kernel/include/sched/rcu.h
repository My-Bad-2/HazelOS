#include "sched/process.h"
#ifndef KERNEL_SCHED_RCU_H
#define KERNEL_SCHED_RCU_H 1

#include <stdatomic.h>
#include <stddef.h>
#include <stdint.h>

#include "libs/dlist.h"
#include "libs/slist.h"
#include "libs/spinlock.h"

#ifdef __cplusplus
extern "C" {
#endif

struct completion {
    uint32_t done;
    spinlock_t lock;
    struct dlist_head wait;
};

struct completion_waiter {
    struct dlist_head list;
    struct thread* task;
};

void init_completion(struct completion* x);
void wait_for_completion(struct completion* x);
void complete(struct completion* x);

struct rcu_head {
    struct slist_node node;
    void (*func)(struct rcu_head*);
};

struct rcu_node {
    spinlock_t lock;
    uint64_t qs_mask;       // Bitmask of CPUs pending QS
    uint64_t qs_mask_init;  // Bitmask of CPUs online for this node
    uint64_t gp_seq;        // Current GP sequence number

    struct rcu_node* parent;
    uint8_t group_num;  // bit index in the parent's qsmask
    uint8_t level;      // 0 = Leaf, N = Root
};

struct rcu_data {
    struct rcu_node* node;  // The leaf node this CPU belongs too
    uint64_t mask;          // Bitmask for this CPU in the leaf node

    struct slist_head pending;       // Pushed by call_rcu()
    struct slist_head waiting;       // waiting for current GP
    struct slist_head next_waiting;  // overflow waiting for the next GP
    struct slist_head done;          // Safe to execute

    uint64_t waiting_gp_seq;  // The GP sequence 'waiting' list is tied to
    uint64_t last_qs_seq;     // Last global GP sequence we acknowledged
    uint64_t nesting;         // Depth of read-side critical sections
    bool qs_pending;          // Does this cpu need to repose a QS?
};

void rcu_init(void);
void rcu_read_lock(void);
void rcu_read_unlock(void);
void call_rcu(struct rcu_head* head, void (*func)(struct rcu_head*));
void rcu_check_callbacks(void);
void synchronize_rcu(void);

struct [[gnu::aligned(CACHE_LINE_SIZE)]] srcu_cpu_data {
    _Atomic(uint64_t) lock_count[2];
    _Atomic(uint64_t) unlock_count[2];

    struct slist_head pending;
};

struct srcu_domain {
    atomic_size_t idx;
    uint32_t cpu_count;

    struct srcu_cpu_data* per_cpu;

    spinlock_t gp_lock;
    atomic_bool gp_active;
    atomic_bool gp_request;
    struct thread* gp_thread;
};

extern struct srcu_domain g_srcu;

void init_srcu_domain(struct srcu_domain* ssp);
int srcu_read_lock(struct srcu_domain* ssp);
void srcu_read_unlock(struct srcu_domain* ssp, int idx);
void synchronize_srcu(struct srcu_domain* ssp);
void call_srcu(struct srcu_domain* ssp, struct rcu_head* head, void (*func)(struct rcu_head*));

struct [[gnu::aligned(CACHE_LINE_SIZE)]] qsbr_cpu_data {
    atomic_size_t local_epoch;
    struct slist_head pending;
};

struct qsbr_domain {
    atomic_size_t global_epoch;
    uint32_t cpu_count;

    struct qsbr_cpu_data* per_cpu;

    spinlock_t gp_lock;
    atomic_bool gp_active;
    atomic_bool gp_request;
    struct thread* gp_thread;
};

extern struct qsbr_domain g_qsbr;

void init_qsbr_domain(struct qsbr_domain* qsd);

void qsbr_online(struct qsbr_domain* qsd);
void qsbr_offline(struct qsbr_domain* qsd);
void qsbr_checkpoint(struct qsbr_domain* qsd);

void synchronize_qsbr(struct qsbr_domain* qsd);
void call_qsbr(struct qsbr_domain* qsd, struct rcu_head* head, void (*func)(struct rcu_head*));

#ifdef __cplusplus
}
#endif

#endif