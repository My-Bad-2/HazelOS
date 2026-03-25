#include "sched/scheduler.h"

#include "cpu/exception.h"
#include "cpu/registers.h"
#include "cpu/smp.h"
#include "libs/log.h"

static irq_return_t reschedule_handler(interrupt_trapframe_t*, void*) {
    per_cpu_data_t* cpu    = smp_current_core();
    cpu->reschedule_needed = true;
    return IRQ_HANDLED;
}

static irq_return_t scheduler_tick(interrupt_trapframe_t*, void*) {
    thread_t* curr = smp_current_core()->curr_thread;

    rcu_check_callbacks();
    schedule();

    return IRQ_HANDLED;
}

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

void scheduler_arch_init(void) {
    irq_config_t config = {
        .polarity = IRQ_POLARITY_HIGH,
        .trigger  = IRQ_TRIGGER_EDGE,
    };

    int res = register_irq(INTERRUPT_IPI_RESCHEDULE, reschedule_handler, nullptr, &config);
    if (res != 0) {
        KLOG_ERROR(
            "SCHEDULER: Failed to install INTERRUPT_IPI_RESCHEDULE (%u) handler\n",
            INTERRUPT_IPI_RESCHEDULE
        );
    }

    res = register_irq(IRQ_TIMER, scheduler_tick, nullptr, &config);
    if (res != 0) {
        KLOG_ERROR("SCHEDULER: Failed to install scheduler_tick handler\n");
    }
}