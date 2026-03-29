#include "sched/scheduler.h"

#include "compiler.h"
#include "cpu/exception.h"
#include "cpu/registers.h"
#include "cpu/smp.h"
#include "libs/log.h"

static irq_return_t reschedule_handler(interrupt_trapframe_t*, void*) {
    smp_current_core()->reschedule_needed = true;
    return IRQ_HANDLED;
}

static irq_return_t scheduler_tick(interrupt_trapframe_t*, void*) {
    rcu_check_callbacks();
    schedule();
    return IRQ_HANDLED;
}

void scheduler_check_reschedule(interrupt_trapframe_t* tf) {
    per_cpu_data_t* cpu = smp_current_core();

    if (likely(!cpu->reschedule_needed || !(tf->rflags & X86_FLAGS_IF))) return;
    if (unlikely(cpu->curr_thread && cpu->curr_thread->preempt_count > 0)) return;

    cpu->reschedule_needed = false;
    schedule();
}

void scheduler_arch_init(void) {
    irq_config_t config = {
        .polarity = IRQ_POLARITY_HIGH,
        .trigger  = IRQ_TRIGGER_EDGE,
    };

    if (register_irq(INTERRUPT_IPI_RESCHEDULE, reschedule_handler, nullptr, &config) != 0)
        KLOG_ERROR("SCHEDULER: Failed to install INTERRUPT_IPI_RESCHEDULE handler\n");

    if (register_irq(IRQ_TIMER, scheduler_tick, nullptr, &config))
        KLOG_ERROR("SCHEDULER: Failed to install scheduler_tick handler\n");
}