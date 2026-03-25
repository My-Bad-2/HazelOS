#include "cpu/smp.h"

#include <stdatomic.h>

#include "arch.h"
#include "cpu/exception.h"
#include "cpu/gdt.h"
#include "cpu/idt.h"
#include "cpu/ioapic.h"
#include "cpu/lapic.h"
#include "cpu/pic.h"
#include "cpu/registers.h"
#include "cpu/simd.h"
#include "cpu/syscalls.h"
#include "drivers/timer.h"
#include "libs/log.h"

static irq_return_t nmi_watchdog_tick(interrupt_trapframe_t*, void*) {
    per_cpu_data_t* cpu = smp_current_core();
    atomic_fetch_add_explicit(&cpu->watchdog.ticks, 1, memory_order_relaxed);
    return IRQ_HANDLED;
}

void arch_init_cpu_state(per_cpu_data_t* cpu) {
    ASSERT(cpu);

    tss_init(&cpu->arch.tss, cpu->kstack_top);
    gdt_init(&cpu->arch.gdt, &cpu->arch.tss);

    if (cpu->is_bsp) {
        idt_init();
        init_isr_registry();
    }
}

void arch_commit_cpu_state(per_cpu_data_t* cpu) {
    ASSERT(cpu);

    gdt_load(&cpu->arch.gdt);
    idt_load();

    lapic_init();
    simd_init();
    syscall_init();

    write_msr(X86_MSR_IA32_TSC_AUX, cpu->cpu_idx);

    if (cpu->is_bsp) {
        pic_init();
        ioapic_init();
        timer_init();

        irq_config_t config = {
            .trigger  = IRQ_TRIGGER_EDGE,
            .polarity = IRQ_POLARITY_HIGH,
        };

        if (register_irq(INTERRUPT_IPI_TLB, ipi_tlb_shootdown_handler, nullptr, nullptr)) {
            PANIC("Failed to register IPI TLB (%zu)!", INTERRUPT_IPI_TLB);
        }

        if (register_irq(IRQ_TIMER, nmi_watchdog_tick, nullptr, &config)) {
            PANIC("Failed to register nmi_watch_dog tick!");
        }
    }

    topology_detect(cpu);
    write_msr(X86_MSR_IA32_GS_BASE, (uint64_t)cpu);

    arch_enable_interrupts();
}

per_cpu_data_t* smp_current_core(void) {
    per_cpu_data_t* data = nullptr;
    asm volatile("mov %%gs:0, %0" : "=r"(data));
    return data;
}

void smp_send_reschedule_ipi(per_cpu_data_t* cpu) {
    lapic_send_ipi(INTERRUPT_IPI_RESCHEDULE, cpu->lapic_id, DELIVERY_MODE_FIXED);
}

static atomic_uint panic_initiator_core = -1;
static atomic_bool system_is_panicking  = false;

void smp_send_panic_ipi(void) {
    bool expected = false;

    if (!atomic_compare_exchange_strong(&system_is_panicking, &expected, true)) {
        arch_halt(false);
    }

    per_cpu_data_t* cpu = smp_current_core();
    atomic_store(&panic_initiator_core, cpu->cpu_idx);

    lapic_send_broadcast_ipi(0, DELIVERY_MODE_NMI);

    arch_halt(false);
}

void nmi_check_for_panic(per_cpu_data_t* cpu) {
    if (atomic_load_explicit(&system_is_panicking, memory_order_acquire)) {
        if (cpu->cpu_idx != atomic_load_explicit(&panic_initiator_core, memory_order_relaxed)) {
            arch_halt(false);
        }
    }
}