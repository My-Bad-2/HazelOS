#include "cpu/smp.h"

#include "cpu/gdt.h"
#include "cpu/registers.h"
#include "libs/log.h"

void arch_init_cpu_state(per_cpu_data_t* cpu) {
    ASSERT(cpu);

    tss_init(&cpu->tss);
    gdt_init(&cpu->gdt, &cpu->tss);

    KLOG_DEBUG(
        "SMP: cpu=%u arch state initialized gdt=%p tss=%p\n",
        cpu->cpu_idx,
        &cpu->gdt,
        &cpu->tss
    );
}

void arch_commit_cpu_state(per_cpu_data_t* cpu) {
    ASSERT(cpu);

    gdt_load(&cpu->gdt);

    uint64_t gs_val = (uint64_t)cpu;
    write_msr(X86_MSR_IA32_GS_BASE, gs_val);

    KLOG_DEBUG("SMP: cpu=%u GDT loaded gs_base=0x%lx\n", cpu->cpu_idx, gs_val);
}

per_cpu_data_t* smp_current_core(void) {
    per_cpu_data_t* data = nullptr;
    asm volatile("mov %%gs:0, %0" : "=r"(data));
    return data;
}