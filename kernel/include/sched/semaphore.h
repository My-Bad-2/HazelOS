#ifndef KERNEL_SCHED_SEMAPHORE_H
#define KERNEL_SCHED_SEMAPHORE_H 1

#include "sched/wait.h"

struct semaphore {
    int count;
    struct wait_queue wait_queue;
};

struct semaphore* sema_create(int value);
void sema_init(struct semaphore* sem, int value);
void sema_destroy(struct semaphore* sem);

void sema_up(struct semaphore* sem);
void sema_down(struct semaphore* sem);
bool sema_try_down(struct semaphore* sem);
int sema_down_timeout(struct semaphore* sem, int64_t timeout_ms);

#endif