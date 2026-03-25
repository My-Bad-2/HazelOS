#include "sched/semaphore.h"

#include "libs/spinlock.h"
#include "sched/process.h"
#include "sched/scheduler.h"
#include "sched/wait.h"

struct semaphore* sema_create(int value) {
    struct semaphore* ret = kmalloc(sizeof(struct semaphore));
    if (!ret) {
        return nullptr;
    }

    sema_init(ret, value);
    return ret;
}

void sema_init(struct semaphore* sem, int value) {
    if (!sem) {
        return;
    }

    sem->count = value;
    wait_queue_init(&sem->wait_queue);
}

void sema_up(struct semaphore* sem) {
    if (!sem) {
        return;
    }

    acquire_qspinlock(&sem->wait_queue.lock);
    sem->count++;
    release_qspinlock(&sem->wait_queue.lock);

    wait_queue_wake_up_one(&sem->wait_queue);
}

void sema_down(struct semaphore* sem) {
    if (!sem) {
        return;
    }

    while (true) {
        acquire_qspinlock(&sem->wait_queue.lock);

        if (sem->count > 0) {
            sem->count--;
            release_qspinlock(&sem->wait_queue.lock);
            return;
        }

        release_qspinlock(&sem->wait_queue.lock);

        thread_sleep_prepare(&sem->wait_queue);
        acquire_qspinlock(&sem->wait_queue.lock);

        bool acquired = false;
        if (sem->count > 0) {
            sem->count--;
            acquired = true;
        }

        release_qspinlock(&sem->wait_queue.lock);

        if (acquired) {
            thread_sleep_finish(&sem->wait_queue);
            return;
        }

        scheduler_yield();
        thread_sleep_finish(&sem->wait_queue);
    }
}

bool sema_try_down(struct semaphore* sem) {
    if (!sem) {
        return false;
    }

    bool acquired = false;

    acquire_qspinlock(&sem->wait_queue.lock);

    if (sem->count > 0) {
        sem->count--;
        acquired = true;
    }

    release_qspinlock(&sem->wait_queue.lock);

    return acquired;
}