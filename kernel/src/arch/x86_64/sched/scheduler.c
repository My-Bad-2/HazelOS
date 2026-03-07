#include "sched/scheduler.h"

#include "cpu/registers.h"
#include "cpu/smp.h"

void scheduler_check_reschedule(interrupt_trapframe_t* tf) {
    per_cpu_data_t* cpu = smp_current_core();

    if (!cpu->reschedule_needed) {
        return;
    }

    if (!(tf->rflags & X86_FLAGS_IF)) {
        return;
    }

    if (cpu->curr_thread && cpu->curr_thread->preempt_count > 0) {
        return;
    }

    cpu->reschedule_needed = false;
    schedule();
}