#include "sched/scheduler.h"

void scheduler_yield(void) {
    asm volatile("int $0x20");
}