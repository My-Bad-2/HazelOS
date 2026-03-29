#ifndef KERNEL_SCHED_WAIT_H
#define KERNEL_SCHED_WAIT_H 1

#include "libs/dlist.h"
#include "libs/spinlock.h"

struct wait_queue {
    qspinlock_t lock;
    struct dlist_head list;
};

static inline void wait_queue_init(struct wait_queue* wq) {
    create_qspinlock(&wq->lock);
    dlist_init(&wq->list);
}

void thread_sleep_prepare(struct wait_queue* wq);
void thread_sleep_finish(struct wait_queue* wq);

void wait_queue_wake_up_one(struct wait_queue* wq);
void wait_queue_wake_up_all(struct wait_queue* wq);
void wait_queue_sleep(struct wait_queue* wq);

/**
 * MACRO: wait_event
 * Safely waits for a condition to become true, preventing lost wakeups.
 */
#define wait_event(wq, condition)     \
    do {                              \
        if (condition) break;         \
        while (true) {                \
            thread_sleep_prepare(wq); \
            if (condition) break;     \
            scheduler_block();        \
        }                             \
        thread_sleep_finish(wq);      \
    } while (0)

/**
 * MACRO: wait_event_timeout
 * Safely waits for a condition, aborting if the timeout expires.
 * 'ret' will be -ETIMEDOUT / ERR_TIMEOUT if the timer fired.
 */
#define wait_event_timeout(wq, condition, timeout_ms, ret) \
    do {                                                   \
        (ret) = 0;                                         \
        if (condition) break;                              \
        while (true) {                                     \
            thread_sleep_prepare(wq);                      \
            if (condition) break;                          \
            (ret) = scheduler_block_timeout(timeout_ms);   \
            if ((ret) < 0) break;                          \
        }                                                  \
        thread_sleep_finish(wq);                           \
    } while (0)

#endif