#include "sched/semaphore.h"

#include <errno.h>

#include "arch.h"
#include "core/errors.h"
#include "libs/dlist.h"
#include "libs/spinlock.h"
#include "sched/process.h"
#include "sched/scheduler.h"
#include "sched/wait.h"

struct semaphore* sema_create(int value) {
    struct semaphore* ret = kmalloc(sizeof(struct semaphore));
    if (!ret) return nullptr;

    sema_init(ret, value);
    return ret;
}

void sema_init(struct semaphore* sem, int value) {
    if (!sem) return;

    sem->count = value;
    wait_queue_init(&sem->wait_queue);
}

void sema_destroy(struct semaphore* sem) {
    if (!sem) return;
    kfree(sem);
}

void sema_up(struct semaphore* sem) {
    if (!sem) return;

    size_t flags = acquire_qinterrupt_lock(&sem->wait_queue.lock);

    if (dlist_empty(&sem->wait_queue.list)) {
        sem->count++;
    } else {
        thread_t* waiter = dlist_first_entry(&sem->wait_queue.list, thread_t, wait_node);

        dlist_del_init(&waiter->wait_node);
        scheduler_unblock(waiter);
    }

    release_qinterrupt_lock(&sem->wait_queue.lock, flags);
}

void sema_down(struct semaphore* sem) {
    sema_down_timeout(sem, -1);
}

bool sema_try_down(struct semaphore* sem) {
    if (!sem) return false;

    bool acquired = false;
    size_t flags  = acquire_qinterrupt_lock(&sem->wait_queue.lock);

    if (sem->count > 0) {
        sem->count--;
        acquired = true;
    }

    release_qinterrupt_lock(&sem->wait_queue.lock, flags);
    return acquired;
}

static void sema_sleep_callback(void* ctx) {
    scheduler_unblock(ctx);
}

int sema_down_timeout(struct semaphore* sem, int64_t timeout_ms) {
    if (!sem) return -EINVAL;

    size_t flags = acquire_qinterrupt_lock(&sem->wait_queue.lock);

    if (sem->count > 0) {
        sem->count--;
        release_qinterrupt_lock(&sem->wait_queue.lock, flags);
        return 0;
    }

    if (timeout_ms == 0) {
        release_qinterrupt_lock(&sem->wait_queue.lock, flags);
        return ERR_TIMEOUT;
    }

    per_cpu_data_t* cpu = smp_current_core();
    thread_t* curr      = cpu->curr_thread;

    dlist_add_tail(&curr->wait_node, &sem->wait_queue.list);
    curr->state            = THREAD_BLOCKED;
    cpu->reschedule_needed = true;

    if (timeout_ms > 0)
        timer_arm_oneshot(
            cpu->timer_manager,
            &curr->sleep_timer,
            timeout_ms,
            sema_sleep_callback,
            curr
        );

    release_qinterrupt_lock(&sem->wait_queue.lock, flags);

    schedule();

    if (timeout_ms > 0) {
        arch_disable_interrupts();
        cpu              = smp_current_core();
        bool timer_fired = timer_cancel(&curr->sleep_timer);
        arch_enable_interrupts();

        if (timer_fired) {
            flags = acquire_qinterrupt_lock(&sem->wait_queue.lock);

            if (dlist_empty(&curr->wait_node)) {
                release_qinterrupt_lock(&sem->wait_queue.lock, flags);
                return 0;
            } else {
                dlist_del_init(&curr->wait_node);
                release_qinterrupt_lock(&sem->wait_queue.lock, flags);
                return ERR_TIMEOUT;
            }
        }
    }

    return 0;
}