#include "cpu/smp.h"

#include <errno.h>
#include <stdatomic.h>
#include <stdint.h>
#include <string.h>

#include "arch.h"
#include "boot/boot.h"
#include "drivers/acpi.h"
#include "drivers/timer.h"
#include "libs/log.h"
#include "libs/spinlock.h"
#include "memory/heap.h"
#include "memory/memory.h"
#include "memory/pagemap.h"
#include "memory/vma.h"
#include "sched/rcu.h"

extern uint8_t bootstrap_stack[];

static per_cpu_data_t* cpu_datas = nullptr;
static bool initialized          = false;

static void init_cpu_state(per_cpu_data_t* cpu) {
    ASSERT(cpu);
    void* stack = nullptr;

    if (cpu->is_bsp) {
        stack = bootstrap_stack;
    } else {
        stack = vmalloc(
            &kernel_space,
            KSTACK_SIZE,
            VMM_FLAG_READ | VMM_FLAG_WRITE | VMM_FLAG_STACK,
            CACHE_WRITE_BACK,
            PAGE_SIZE_SMALL
        );
    }

    if (!stack) {
        errno = ENOMEM;
        PANIC("SMP: failed to allocate kernel stack cpu=%u errno=%d", cpu->cpu_idx, errno);
    }

    cpu->kstack_top = (uintptr_t)stack + KSTACK_SIZE;
    cpu->rcu        = vmalloc(
        &kernel_space,
        sizeof(struct rcu_data),
        VMM_FLAG_READ | VMM_FLAG_WRITE,
        CACHE_WRITE_BACK,
        PAGE_SIZE_SMALL
    );

    create_interrupt_lock(&cpu->lock);

    timer_manager_init(&cpu->timer_manager);
    arch_init_cpu_state(cpu);

    KLOG_DEBUG(
        "SMP: cpu=%u bsp=%d lapic=0x%x stack_top=0x%lx initialized\n",
        cpu->cpu_idx,
        cpu->is_bsp,
        cpu->lapic_id,
        cpu->kstack_top
    );
}

static void commit_cpu_state(per_cpu_data_t* cpu) {
    ASSERT(cpu);

    arch_commit_cpu_state(cpu);

    KLOG_DEBUG("SMP: cpu=%u committed arch state\n", cpu->cpu_idx);
}

void smp_init(void) {
    if (!mp_request.response) {
        errno = EIO;
        PANIC("SMP: missing Limine MP response errno=%d\n", errno);
    }

    size_t num_cpus = mp_request.response->cpu_count;

    if (num_cpus == 0) {
        KLOG_WARN("SMP: firmware reported zero CPUs, defaulting to 1\n");
        num_cpus = 1;
    }

    KLOG_INFO("SMP: initializing %zu CPU(s)\n", num_cpus);

    cpu_datas = kmalloc(sizeof(per_cpu_data_t) * num_cpus);

    if (!cpu_datas) {
        errno = ENOMEM;
        PANIC("SMP: failed to allocate per-cpu array count=%zu errno=%d\n", num_cpus, errno);
    }

    memset(cpu_datas, 0, num_cpus * sizeof(per_cpu_data_t));

    acpi_early_init();
    topology_detect(cpu_datas);

    for (uint32_t i = 0; i < num_cpus; ++i) {
        struct limine_mp_info* info = mp_request.response->cpus[i];
        per_cpu_data_t* data        = &cpu_datas[i];

        info->extra_argument = (uintptr_t)data;

        data->lapic_id = info->lapic_id;
        data->cpu_idx  = i;
        data->self     = data;

        data->is_bsp = (mp_request.response->bsp_lapic_id == info->lapic_id);
        atomic_store_explicit(&data->is_online, data->is_bsp, memory_order_seq_cst);

        KLOG_DEBUG(
            "SMP: cpu=%u lapic=0x%x bsp=%d online=%d (pre-init)\n",
            data->cpu_idx,
            data->lapic_id,
            data->is_bsp,
            atomic_load_explicit(&data->is_online, memory_order_relaxed)
        );

        init_cpu_state(data);

        if (data->is_bsp) {
            commit_cpu_state(data);
        }

        if (!atomic_load_explicit(&data->is_online, memory_order_acquire)) {
            KLOG_WARN("SMP: cpu=%u offline after init\n", data->cpu_idx);
            arch_pause();
        } else if (data->is_bsp) {
            KLOG_INFO("SMP: BSP cpu=%u online\n", data->cpu_idx);
        } else {
            KLOG_DEBUG("SMP: cpu=%u online\n", data->cpu_idx);
        }
    }

    topology_map_siblings(&cpu_datas, num_cpus);

    initialized = true;

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