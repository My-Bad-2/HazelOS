#include "sched/scheduler.h"

#include "cpu/registers.h"
#include "cpu/smp.h"

void scheduler_check_reschedule(interrupt_trapframe_t* tf) {
    per_cpu_data_t* cpu = smp_current_core();

    if (!cpu->reschedule_needed) {
        return;
    }

    // If the code we interrupted has disabled interrupts, it is strictly atomic. We must not
    // preempt it.
    if (!(tf->rflags & X86_FLAGS_IF)) {
        return;
    }

    cpu->reschedule_needed = false;
    schedule();
}