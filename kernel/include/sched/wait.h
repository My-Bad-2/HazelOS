#ifndef KERNEL_SCHED_WAIT_H
#define KERNEL_SCHED_WAIT_H 1

#include "libs/dlist.h"
#include "libs/hashtable.h"
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

struct vmo_page_waiter {
    struct hlist_node node;
    struct thread* thread;
    struct vm_object* vmo;
    size_t offset;
};

struct [[gnu::aligned(CACHE_LINE_SIZE)]] page_wait_bucket {
    qspinlock_t lock;
    struct hlist_head waiters;
};

void vmm_wait_table_init(void);
void sched_prepare_page_wait(struct vmo_page_waiter* waiter, struct vm_object* vmo, size_t offset);
void sched_commit_page_wait(void);
void sched_abort_page_wait(struct vmo_page_waiter* waiter);
void sched_wake_threads_waiting_on_page(struct vm_object* vmo, size_t base_offset, size_t length);

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