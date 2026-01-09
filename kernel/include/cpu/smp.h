#include <stdatomic.h>
#ifndef KERNEL_CPU_H
#define KERNEL_CPU_H 1

#include <stddef.h>

#ifdef __x86_64__
#include "cpu/gdt.h"
#endif

#ifdef __cplusplus
extern "C" {
#endif

typedef struct per_cpu_data {
    struct per_cpu_data* self;
    uintptr_t stack_top;

    uint32_t cpu_idx;
    uint32_t lapic_id;

    atomic_int is_online;
    int is_bsp;

#ifdef __x86_64__
    gdt_table_t gdt;
    tss_t tss;
#endif
} per_cpu_data_t;

void smp_init(void);

void arch_init_cpu_state(per_cpu_data_t* cpu);
void arch_commit_cpu_state(per_cpu_data_t* cpu);

per_cpu_data_t* smp_current_core(void);
uint32_t smp_current_core_idx(void);

#ifdef __cplusplus
}
#endif

#endif