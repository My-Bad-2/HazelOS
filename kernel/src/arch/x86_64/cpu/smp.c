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
#include "libs/log.h"

void arch_init_cpu_state(per_cpu_data_t* cpu) {
    ASSERT(cpu);

    tss_init(&cpu->arch.tss, cpu->kstack_top);
    gdt_init(&cpu->arch.gdt, &cpu->arch.tss);
    idt_init();

    init_isr_registry();

    KLOG_DEBUG(
        "SMP: cpu=%u arch state initialized gdt=%p tss=%p\n",
        cpu->cpu_idx,
        &cpu->arch.gdt,
        &cpu->arch.tss
    );
}

void arch_commit_cpu_state(per_cpu_data_t* cpu) {
    ASSERT(cpu);

    gdt_load(&cpu->arch.gdt);
    idt_load();
    pic_init();

    lapic_init();
    ioapic_init();
    simd_init();
    syscall_init();

    topology_detect(cpu);

    uint64_t gs_val = (uint64_t)cpu;
    write_msr(X86_MSR_IA32_GS_BASE, gs_val);

    KLOG_DEBUG("SMP: cpu=%u GDT loaded gs_base=0x%lx\n", cpu->cpu_idx, gs_val);

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