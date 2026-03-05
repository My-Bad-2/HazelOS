#include "cpu/smp.h"

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

    if (cpu->is_bsp) {
        pic_init();
        ioapic_init();
        timer_init();
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