#ifndef KERNEL_SCHED_WAIT_H
#define KERNEL_SCHED_WAIT_H 1

#include "libs/dlist.h"
#include "libs/spinlock.h"

struct wait_queue {
    spinlock_t lock;
    struct dlist_head list;
};

static inline void wait_queue_init(struct wait_queue* wq) {
    create_spinlock(&wq->lock);
    dlist_init(&wq->list);
}

#endif