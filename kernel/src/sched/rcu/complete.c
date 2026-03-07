#include "arch.h"
#include "sched/rcu.h"
#include "sched/scheduler.h"

void init_completion(struct completion* x) {
    x->done = 0;
    create_spinlock(&x->lock);
    dlist_init(&x->wait);
}

void complete(struct completion* x) {
    arch_disable_interrupts();
    acquire_spinlock(&x->lock);

    x->done++;

    if (!dlist_empty(&x->wait)) {
        struct dlist_head* first    = x->wait.next;
        struct completion_waiter* w = dlist_entry(first, struct completion_waiter, list);

        scheduler_unblock(w->task);
    }

    release_spinlock(&x->lock);
    arch_enable_interrupts();
}

void wait_for_completion(struct completion* x) {
    struct completion_waiter w;
    thread_t* curr = smp_current_core()->curr_thread;

    w.task = curr;
    dlist_init(&w.list);

    arch_disable_interrupts();
    acquire_spinlock(&x->lock);

    if (x->done > 0) {
        x->done--;
        release_spinlock(&x->lock);
        arch_enable_interrupts();
        return;
    }

    dlist_add_tail(&w.list, &x->wait);

    while (x->done == 0) {
        curr->state = THREAD_BLOCKED;

        release_spinlock(&x->lock);
        schedule();
        acquire_spinlock(&x->lock);
    }

    x->done--;
    dlist_del(&w.list);

    release_spinlock(&x->lock);
    arch_enable_interrupts();
}