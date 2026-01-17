#ifndef KERNEL_SMP_H
#define KERNEL_SMP_H 1

#include <stdatomic.h>
#include <stddef.h>

#include "drivers/timer.h"
#include "libs/rb_tree.h"
#include "libs/spinlock.h"
#include "sched/process.h"

#ifdef __x86_64__
#include "cpu/gdt.h"
#include "cpu/topology.h"
#endif

#ifdef __cplusplus
extern "C" {
#endif

struct cpu_topology;

typedef struct [[gnu::aligned(CACHE_LINE_SIZE)]] per_cpu_data {
    struct per_cpu_data* self;
    uintptr_t stack_top;

    uint32_t cpu_idx;
    uint32_t lapic_id;

    uint32_t thread_count;
    uint32_t balance_counter;
    size_t cpu_load;

    atomic_int is_online;
    bool is_bsp;
    bool reschedule_needed;
    bool is_nohz_active;

#ifdef __x86_64__
    gdt_table_t gdt;
    tss_t tss;

    struct cpu_topology topology;
#endif

    struct rb_root_cached cfs_tree;
    size_t min_vruntime;

    struct rb_root_cached rt_tree;
    struct rb_root_cached dl_tree;

    thread_t* curr_thread;
    thread_t* idle_thread;

    interrupt_lock_t lock;
    timer_manager_t timer_manager;
} per_cpu_data_t;

void smp_init(void);

void arch_init_cpu_state(per_cpu_data_t* cpu);
void arch_commit_cpu_state(per_cpu_data_t* cpu);

per_cpu_data_t* smp_current_core(void);
per_cpu_data_t* smp_get_core(uint32_t idx);
uint32_t smp_current_core_idx(void);

void topology_detect(per_cpu_data_t* cpu);
void topology_init_masks(per_cpu_data_t** all_cpus, size_t count);
void topology_map_siblings(per_cpu_data_t** all_cpus, size_t count);

void smp_send_reschedule_ipi(per_cpu_data_t* cpu);

#ifdef __cplusplus
}
#endif

#endif