#ifndef KERNEL_SCHED_RCU_H
#define KERNEL_SCHED_RCU_H 1

#include <stdatomic.h>
#include <stddef.h>
#include <stdint.h>

#include "libs/spinlock.h"

#ifdef __cplusplus
extern "C" {
#endif

#define RCU_CALLBACK_RING_SIZE 4096
#define RCU_QSBR_OFFLINE_EPOCH 0

struct rcu_head {
    void (*func)(struct rcu_head*);
};

struct rcu_callback_batch {
    struct rcu_head* buffer[RCU_CALLBACK_RING_SIZE];
    atomic_size_t head;
    atomic_size_t tail;
    spinlock_t lock;
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

extern struct srcu_domain g_srcu;
extern struct qsbr_domain g_qsbr;

void rcu_init(void);

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

#ifdef __cplusplus
}
#endif

#endif