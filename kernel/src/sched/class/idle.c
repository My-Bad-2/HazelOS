#include "sched/sched_class.h"

struct sched_class idle_sched_class = {
    .name           = "IDLE",
    .priority       = -1,
    .policy_id      = SCHED_IDLE,
    .next           = nullptr,
    .enqueue_task   = nullptr,
    .dequeue_task   = nullptr,
    .yield_task     = nullptr,
    .task_tick      = nullptr,
    .pick_next_task = nullptr,
    .steal_task     = nullptr,
    .check_preempt  = nullptr
};