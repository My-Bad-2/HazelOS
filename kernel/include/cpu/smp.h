#include "sched/rcu.h"
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
    thread_t* curr_thread;
    thread_t* idle_thread;

    uintptr_t kstack_top;
    uintptr_t scratch_user_rsp;

    qspinlock_t lock;

    uint32_t cpu_idx;
    uint32_t lapic_id;

    bool is_bsp;
    bool reschedule_needed;
    bool is_nohz_active;
    uint8_t _pad0;
    uint32_t qspin_node_idx;

    size_t min_vruntime;

    struct rb_root_cached cfs_tree;
    struct rb_root_cached rt_tree;
    struct rb_root_cached dl_tree;
    struct rcu_data* rcu;

    timer_manager_t* timer_manager;

    atomic_size_t cpu_load;
    size_t last_load_update;  // Timestamp of last update
    size_t runnable_sum;      // Accumulated runnable time in current window
    size_t period_contrib;    // Partial time in current 1ms window

    uint32_t thread_count;
    uint32_t balance_counter;
    atomic_int is_online;

    struct arch_cpu_data arch;
    struct mcs_node qspin_nodes[MAX_QSPIN_NODES];
} per_cpu_data_t;

void smp_init(void);

void arch_init_cpu_state(per_cpu_data_t* cpu);
void arch_commit_cpu_state(per_cpu_data_t* cpu);

per_cpu_data_t* smp_current_core(void);
per_cpu_data_t* smp_get_core(uint32_t idx);
uint32_t smp_current_core_idx(void);

void topology_detect(per_cpu_data_t* cpu);
void topology_init_masks(per_cpu_data_t** all_cpus, size_t count);
void topology_map_siblings(per_cpu_data_t* all_cpus, size_t count);

void smp_send_reschedule_ipi(per_cpu_data_t* cpu);

#ifdef __cplusplus
}
#endif

#endif