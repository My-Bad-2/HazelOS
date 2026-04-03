#include "cpu/smp.h"
#include "libs/spinlock.h"
#include "sched/rcu.h"
#include "sched/scheduler.h"

void init_completion(struct completion* x) {
    x->done = 0;
    create_qspinlock(&x->lock);
    dlist_init(&x->wait);
}

void complete(struct completion* x) {
    size_t flags = acquire_qinterrupt_lock(&x->lock);

    if (x->done < UINT32_MAX) x->done++;

    struct dlist_head* iter = x->wait.next;
    while (iter != &x->wait) {
        struct completion_waiter* w = dlist_entry(iter, struct completion_waiter, list);
        if (w->task->state == THREAD_BLOCKED) {
            scheduler_unblock(w->task);
            break;
        }

        iter = iter->next;
    }

    release_qinterrupt_lock(&x->lock, flags);
}

void wait_for_completion(struct completion* x) {
    size_t flags = acquire_qinterrupt_lock(&x->lock);

    if (x->done > 0) {
        x->done--;
        release_qinterrupt_lock(&x->lock, flags);
        return;
    }

    struct completion_waiter w;
    thread_t* curr = smp_current_core()->curr_thread;

    w.task = curr;
    dlist_init(&w.list);
    dlist_add_tail(&w.list, &x->wait);

    while (x->done == 0) {
        curr->state = THREAD_BLOCKED;

        release_qinterrupt_lock(&x->lock, flags);
        schedule();
        flags = acquire_qinterrupt_lock(&x->lock);
    }

    x->done--;
    dlist_del(&w.list);

    release_qinterrupt_lock(&x->lock, flags);
}