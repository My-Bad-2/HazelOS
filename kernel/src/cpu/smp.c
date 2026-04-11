#include "cpu/smp.h"

#include <stdatomic.h>
#include <stdint.h>
#include <string.h>

#include "arch.h"
#include "boot/boot.h"
#include "libs/kobject.h"
#include "libs/log.h"
#include "libs/spinlock.h"
#include "memory/arch_mmu.h"
#include "memory/heap.h"
#include "memory/pagemap.h"
#include "memory/vmm.h"
#include "sched/rcu.h"
#include "sched/scheduler.h"

extern uint8_t bootstrap_stack[];

static per_cpu_data_t* cpu_datas = nullptr;
static bool initialized          = false;

static void ap_entry_point(struct limine_mp_info* info) {
    per_cpu_data_t* cpu = (per_cpu_data_t*)info->extra_argument;

    arch_mmu_init();

    pagemap_t* map = vmm_get_kernel_pagemap();
    pagemap_load(map);

    arch_commit_cpu_state(cpu);
    scheduler_init_per_cpu(cpu);
    atomic_store_explicit(&cpu->is_online, 1, memory_order_release);

    arch_halt(true);
}

static void init_cpu_state(per_cpu_data_t* cpu) {
    ASSERT(cpu);
    cpu->rcu = kmalloc(sizeof(struct rcu_data));
    memset(cpu->rcu, 0, sizeof(struct rcu_data));

    create_qspinlock(&cpu->lock);

    cpu->timer_manager = kmalloc(sizeof(timer_manager_t));

    timer_manager_init(cpu->timer_manager);
    arch_init_cpu_state(cpu);
}

void smp_init(void) {
    if (!mp_request.response) {
        PANIC("SMP: missing Limine MP response!\n");
    }

    size_t num_cpus = mp_request.response->cpu_count;

    if (num_cpus == 0) {
        num_cpus = 1;
    }

    koid_init();

    cpu_datas = kmalloc(sizeof(per_cpu_data_t) * num_cpus);
    memset(cpu_datas, 0, num_cpus * sizeof(per_cpu_data_t));

    for (uint32_t i = 0; i < num_cpus; ++i) {
        struct limine_mp_info* info = mp_request.response->cpus[i];
        per_cpu_data_t* cpu         = &cpu_datas[i];

        info->extra_argument = (uintptr_t)cpu;

        cpu->lapic_id = info->lapic_id;
        cpu->cpu_idx  = i;
        cpu->self     = cpu;
        cpu->is_bsp   = (mp_request.response->bsp_lapic_id == info->lapic_id);

        if (cpu->is_bsp) {
            scheduler_init_kernel_process();
        }

        init_cpu_state(cpu);
    }

    for (uint32_t i = 0; i < num_cpus; ++i) {
        struct limine_mp_info* info = mp_request.response->cpus[i];
        per_cpu_data_t* cpu         = &cpu_datas[i];

        if (cpu->is_bsp) {
            arch_commit_cpu_state(cpu);
            scheduler_init();
            scheduler_init_per_cpu(cpu);
            atomic_store_explicit(&cpu->is_online, cpu->is_bsp, memory_order_seq_cst);
            KLOG_INFO("SMP: BSP cpu=%u online\n", cpu->cpu_idx);
        } else {
            atomic_store_explicit(&cpu->is_online, 0, memory_order_relaxed);
            info->goto_address = ap_entry_point;
        }
    }

    for (uint32_t i = 0; i < num_cpus; ++i) {
        while (!atomic_load_explicit(&cpu_datas[i].is_online, memory_order_acquire)) {
            arch_pause();
        }
    }

    initialized = true;
    topology_map_siblings(cpu_datas, num_cpus);

    KLOG_INFO("SMP: initialization complete (%zu CPU(s))\n", num_cpus);
}

uint32_t smp_current_core_idx(void) {
    if (!initialized) {
        return 0;
    }

    return smp_current_core()->cpu_idx;
}

uint32_t arch_get_core_idx(void) {
    return smp_current_core_idx();
}

per_cpu_data_t* smp_get_core(uint32_t idx) {
    if (!cpu_datas) {
        return nullptr;
    }

    if (idx >= mp_request.response->cpu_count) {
        return nullptr;
    }

    return &cpu_datas[idx];
}

bool smp_is_initialized(void) {
    return initialized;
}