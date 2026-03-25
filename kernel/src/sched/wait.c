#include "sched/wait.h"

#include "arch.h"
#include "libs/dlist.h"
#include "libs/spinlock.h"
#include "sched/process.h"
#include "sched/sched_class.h"
#include "sched/scheduler.h"

void thread_sleep_prepare(struct wait_queue* wq) {
    per_cpu_data_t* cpu = smp_current_core();
    thread_t* curr      = cpu->curr_thread;

    acquire_qspinlock(&wq->lock);

    if (dlist_empty(&curr->wait_node)) {
        dlist_add_tail(&curr->wait_node, &wq->list);
    }

    arch_disable_interrupts();

    curr->state = THREAD_BLOCKED;

    release_qspinlock(&wq->lock);
}

void thread_sleep_finish(struct wait_queue* wq) {
    per_cpu_data_t* cpu = smp_current_core();
    thread_t* curr      = cpu->curr_thread;

    acquire_qspinlock(&wq->lock);

    curr->state = THREAD_RUNNING;

    if (!dlist_empty(&curr->wait_node)) {
        dlist_del(&curr->wait_node);
        dlist_init(&curr->wait_node);
    }

    release_qspinlock(&wq->lock);
    arch_enable_interrupts();
}

void wait_queue_wake_up_all(struct wait_queue* wq) {
    if (!wq) return;
    acquire_qspinlock(&wq->lock);

    while (!dlist_empty(&wq->list)) {
        struct dlist_head* node = wq->list.next;
        thread_t* waiter        = dlist_entry(node, thread_t, wait_node);

        dlist_del(node);
        dlist_init(&waiter->wait_node);

        scheduler_unblock(waiter);
    }

    release_qspinlock(&wq->lock);
}

void wait_queue_sleep(struct wait_queue* wq) {
    if (!wq) return;

    per_cpu_data_t* cpu = smp_current_core();
    thread_t* curr      = cpu->curr_thread;

    acquire_qspinlock(&wq->lock);

    if (dlist_empty(&curr->wait_node)) {
        dlist_add_tail(&curr->wait_node, &wq->list);
    }

    arch_disable_interrupts();
    curr->state = THREAD_BLOCKED;
    release_qspinlock(&wq->lock);

    scheduler_yield();

    acquire_qspinlock(&wq->lock);

    if (!dlist_empty(&curr->wait_node)) {
        dlist_del(&curr->wait_node);
        dlist_init(&curr->wait_node);
    }

    release_qspinlock(&wq->lock);

    arch_enable_interrupts();
}

void wait_queue_wake_up_one(struct wait_queue* wq) {
    if (!wq) {
        return;
    }

    acquire_qspinlock(&wq->lock);

    if (!dlist_empty(&wq->list)) {
        struct dlist_head* node = wq->list.next;
        thread_t* curr          = dlist_entry(node, thread_t, wait_node);

        dlist_del(node);
        dlist_init(&curr->wait_node);

        scheduler_unblock(curr);
    }

    release_qspinlock(&wq->lock);
}