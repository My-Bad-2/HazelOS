#include "sched/wait.h"

#include "arch.h"
#include "compiler.h"
#include "libs/dlist.h"
#include "libs/spinlock.h"
#include "sched/process.h"
#include "sched/sched_class.h"
#include "sched/scheduler.h"

void thread_sleep_prepare(struct wait_queue* wq) {
    if (unlikely(!wq)) return;

    per_cpu_data_t* cpu = smp_current_core();
    thread_t* curr      = cpu->curr_thread;

    size_t flags = acquire_qinterrupt_lock(&wq->lock);

    if (dlist_empty(&curr->wait_node)) dlist_add_tail(&curr->wait_node, &wq->list);

    curr->state = THREAD_BLOCKED;
    release_qinterrupt_lock(&wq->lock, flags);
}

void thread_sleep_finish(struct wait_queue* wq) {
    if (unlikely(!wq)) return;

    per_cpu_data_t* cpu = smp_current_core();
    thread_t* curr      = cpu->curr_thread;

    size_t flags = acquire_qinterrupt_lock(&wq->lock);

    curr->state = THREAD_RUNNING;
    if (!dlist_empty(&curr->wait_node)) dlist_del_init(&curr->wait_node);

    release_qinterrupt_lock(&wq->lock, flags);
    arch_enable_interrupts();
}

void wait_queue_wake_up_one(struct wait_queue* wq) {
    if (unlikely(!wq)) return;

    size_t flags = acquire_qinterrupt_lock(&wq->lock);

    if (!dlist_empty(&wq->list)) {
        thread_t* curr = dlist_first_entry(&wq->list, thread_t, wait_node);
        dlist_del_init(&curr->wait_node);
        scheduler_unblock(curr);
    }

    release_qinterrupt_lock(&wq->lock, flags);
}

void wait_queue_wake_up_all(struct wait_queue* wq) {
    if (unlikely(!wq)) return;

    struct dlist_head local_list;
    dlist_init(&local_list);

    acquire_qspinlock(&wq->lock);

    while (!dlist_empty(&wq->list)) {
        dlist_replace_init(&wq->list, &local_list);
    }

    release_qspinlock(&wq->lock);

    struct dlist_head *pos, *n;
    dlist_for_each_safe(pos, n, &local_list) {
        thread_t* waiter = dlist_entry(pos, thread_t, wait_node);

        dlist_init(&waiter->wait_node);
        scheduler_unblock(waiter);
    }
}

void wait_queue_sleep(struct wait_queue* wq) {
    if (unlikely(!wq)) return;

    thread_sleep_prepare(wq);
    scheduler_block();
    thread_sleep_finish(wq);
}