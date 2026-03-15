#include "cpu/lapic.h"

#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>

#include "arch.h"
#include "cpu/cpu.h"
#include "cpu/exception.h"
#include "cpu/registers.h"
#include "drivers/arch_timer.h"
#include "drivers/timer.h"
#include "libs/log.h"
#include "libs/mmio.h"
#include "libs/spinlock.h"
#include "memory/memory.h"
#include "memory/pagemap.h"
#include "memory/paging.h"
#include "memory/vma.h"
#include "memory/vmm.h"

#include "internal/lapic.h"

static void* virt_base       = nullptr;
static uint32_t freq_hz      = 0;
static uint32_t ticks_per_us = 0;

static bool x2apic_enabled         = false;
static bool tsc_deadline_supported = false;
static bool warned_no_freq         = false;
static bool warned_deadline_mode   = false;

static interrupt_lock_t lock;
static timer_mode_t curr_mode;

static uint32_t lapic_read(size_t offset) {
    if (x2apic_enabled) {
        return (uint32_t)read_msr(LAPIC_X2APIC_MSR_BASE + (offset >> 4));
    }

    return mmio_read32((void*)((uintptr_t)virt_base + offset));
}

static void lapic_write(size_t offset, uint32_t val) {
    if (x2apic_enabled) {
        write_msr(LAPIC_X2APIC_MSR_BASE + (offset >> 4), val);
    } else {
        mmio_write32((void*)((uintptr_t)virt_base + offset), val);
    }
}

static inline void lapic_wait_for_ipi_send(void) {
    while (lapic_read(LAPIC_REG_IRQ_CMD_LOW) & ICR_DELIVERY_PENDING) {
        arch_pause();
    }
}

static void apic_error_handler(interrupt_trapframe_t*, void*) {
    lapic_write(LAPIC_REG_ERROR_STATUS, 0);
    uint32_t error_flags = lapic_read(LAPIC_REG_ERROR_STATUS);

    if (!error_flags) {
        return;
    }

    const size_t buf_size = 512;
    char buf[512];
    size_t offset = 0;

#define APPEND_ERR(...)                                                                      \
    do {                                                                                     \
        if (offset < buf_size) {                                                             \
            int written = snprintf(buf + offset, buf_size - offset, __VA_ARGS__);            \
            if (written > 0) {                                                               \
                offset += ((size_t)written < (buf_size - offset)) ? (size_t)written          \
                                                                  : (buf_size - offset - 1); \
            }                                                                                \
        }                                                                                    \
    } while (0)

    APPEND_ERR("\n[APIC ERROR] CPU %d ESR: 0x%08x | Flags: ", arch_get_core_idx(), error_flags);

    if (error_flags & LAPIC_ERR_SEND_CS_ERROR) {
        APPEND_ERR("[Send Checksum] ");
    }

    if (error_flags & LAPIC_ERR_RECV_CS_ERROR) {
        APPEND_ERR("[Recv Checksum] ");
    }

    if (error_flags & LAPIC_ERR_SEND_ACCEPT_ERROR) {
        APPEND_ERR("[Send Accept] ");
    }

    if (error_flags & LAPIC_ERR_RECV_ACCEPT_ERROR) {
        APPEND_ERR("[Recv Accept] ");
    }

    if (error_flags & LAPIC_ERR_REDIRECTABLE_IPI) {
        APPEND_ERR("[Redirectable IPI] ");
    }

    if (error_flags & LAPIC_ERR_SEND_ILLEGAL_VECTOR) {
        APPEND_ERR("[Send Illegal Vec] ");
    }

    if (error_flags & LAPIC_ERR_RECV_ILLEGAL_VECTOR) {
        APPEND_ERR("[Recv Illegal Vec] ");
    }

    if (error_flags & LAPIC_ERR_ILLEGAL_REGISTER) {
        APPEND_ERR("[Illegal Reg Access] ");
    }

    APPEND_ERR("\n");
    KLOG_ERROR("%s", buf);
#undef APPEND_ERR
}

static void apic_timer_handler(interrupt_trapframe_t*, void*) {
    timer_tick();
}

void lapic_init(void) {
    KLOG_INIT_START("LAPIC");
    tsc_deadline_supported = cpu_has_feature(FEATURE_TSC_DEADLINE);

    uint64_t apic_base_msr  = read_msr(X86_MSR_IA32_APIC_BASE);
    bool is_bsp             = (apic_base_msr & IA32_APIC_BASE_BSP) != 0;
    bool has_x2apic_support = cpu_has_feature(FEATURE_X2APIC);

    if (is_bsp && has_x2apic_support) {
        x2apic_enabled = true;
    }

    if (!x2apic_enabled && !virt_base) {
        uintptr_t phys_base = apic_base_msr & X86_PAGE_ADDRESS_MASK;
        virt_base           = vmalloc(
            kernel_space,
            nullptr,
            PAGE_SIZE_SMALL,
            VMM_FLAG_MMIO,
            CACHE_MMIO,
            PAGE_SIZE_SMALL
        );

        if (!virt_base) {
            KLOG_INIT_FAIL();
            PANIC("LAPIC: Out of memory for MMIO mapping.");
        }

        pagemap_map_args_t args = {
            .virt_addr = virt_base,
            .phys_addr = (void*)phys_base,
            .length    = PAGE_SIZE_SMALL,
            .flags     = VMM_FLAG_READ | VMM_FLAG_WRITE | VMM_FLAG_GLOBAL,
            .cache     = CACHE_MMIO,
            .page_size = PAGE_SIZE_SMALL
        };

        if (!pagemap_map(vmm_get_kernel_pagemap(), &args)) {
            KLOG_INIT_FAIL();
            PANIC("LAPIC: Failed to map MMIO.");
        }
    }

    apic_base_msr |= IA32_APIC_BASE_XAPIC_ENABLE;
    if (x2apic_enabled) {
        apic_base_msr |= IA32_APIC_BASE_X2APIC_ENABLE;
    }

    write_msr(X86_MSR_IA32_APIC_BASE, apic_base_msr);

    lapic_write(
        LAPIC_REG_SPURIOUS_IRQ,
        SVR_SPURIOUS_VECTOR(INTERRUPT_APIC_SPURIOUS) | SVR_APIC_ENABLE
    );

    lapic_set_tpr(0);

    lapic_write(LAPIC_REG_LVT_ERROR, LVT_VECTOR(INTERRUPT_APIC_ERROR));
    lapic_write(LAPIC_REG_LVT_PERF, LVT_VECTOR(INTERRUPT_APIC_PMI) | LVT_MASKED);

    uint32_t timer_val = LVT_VECTOR(INTERRUPT_APIC_TIMER) | LVT_MASKED;
    if (tsc_deadline_supported) {
        timer_val &= ~LVT_MASKED;
        timer_val |= LVT_TIMER_MODE_TSC_DEADLINE;
        asm volatile("mfence" ::: "memory");
    }

    lapic_write(LAPIC_REG_LVT_TIMER, timer_val);

    create_interrupt_lock(&lock);

    register_interrupt_handler(
        INTERRUPT_APIC_TIMER,
        apic_timer_handler,
        nullptr,
        IRQ_TRIGGER_EDGE,
        IRQ_POLARITY_HIGH
    );

    register_interrupt_handler(
        INTERRUPT_APIC_ERROR,
        apic_error_handler,
        nullptr,
        IRQ_TRIGGER_EDGE,
        IRQ_POLARITY_HIGH
    );

    KLOG_INIT_OK();
}

uint32_t lapic_local_id(void) {
    uint32_t id = lapic_read(LAPIC_REG_ID);

    return x2apic_enabled ? id : (id >> 24);
}

void lapic_send_eoi(void) {
    lapic_write(LAPIC_REG_EOI, 0);
}

void lapic_set_tpr(uint8_t priority) {
    lapic_write(LAPIC_REG_TASK_PRIORITY, priority);
}

uint8_t lapic_get_tpr(void) {
    return lapic_read(LAPIC_REG_TASK_PRIORITY) & 0xFF;
}

void lapic_send_ipi(uint8_t vector, uint32_t dest_lapic_id, apic_interrupt_delivery_mode_t mode) {
    uint32_t req = ICR_LEVEL_ASSERT | ICR_DELIVERY_MODE(mode) | ICR_VECTOR(vector) | ICR_DST_NONE;

    if (x2apic_enabled) {
        write_msr(LAPIC_X2APIC_MSR_ICR, ((uint64_t)dest_lapic_id << 32) | req);
    } else {
        acquire_interrupt_lock(&lock);
        lapic_write(LAPIC_REG_IRQ_CMD_HIGH, ICR_DST(dest_lapic_id));
        lapic_write(LAPIC_REG_IRQ_CMD_LOW, req);
        lapic_wait_for_ipi_send();
        release_interrupt_lock(&lock);
    }
}

void lapic_send_self_ipi(uint8_t vector, apic_interrupt_delivery_mode_t mode) {
    if (x2apic_enabled) {
        write_msr(LAPIC_X2APIC_MSR_SELF_IPI, vector);
        return;
    }

    uint32_t req = ICR_LEVEL_ASSERT | ICR_DELIVERY_MODE(mode) | ICR_VECTOR(vector) | ICR_DST_SELF;
    acquire_interrupt_lock(&lock);
    lapic_write(LAPIC_REG_IRQ_CMD_LOW, req);
    lapic_wait_for_ipi_send();
    release_interrupt_lock(&lock);
}

void lapic_send_broadcast_ipi(uint8_t vector, apic_interrupt_delivery_mode_t mode) {
    uint32_t req =
        ICR_LEVEL_ASSERT | ICR_DELIVERY_MODE(mode) | ICR_VECTOR(vector) | ICR_DST_ALL_MINUS_SELF;

    if (x2apic_enabled) {
        write_msr(LAPIC_X2APIC_MSR_ICR, req);
    } else {
        acquire_interrupt_lock(&lock);
        lapic_write(LAPIC_REG_IRQ_CMD_LOW, req);
        lapic_wait_for_ipi_send();
        release_interrupt_lock(&lock);
    }
}

void lapic_send_broadcast_self_ipi(uint8_t vector, apic_interrupt_delivery_mode_t mode) {
    uint32_t req = ICR_LEVEL_ASSERT | ICR_DELIVERY_MODE(mode) | ICR_VECTOR(vector) | ICR_DST_ALL;

    if (x2apic_enabled) {
        write_msr(LAPIC_X2APIC_MSR_ICR, req);
    } else {
        acquire_interrupt_lock(&lock);
        lapic_write(LAPIC_REG_IRQ_CMD_LOW, req);
        lapic_wait_for_ipi_send();
        release_interrupt_lock(&lock);
    }
}

void lapic_send_init(uint32_t dest_lapic_id) {
    // Mode 5 = INIT, Level Assert
    lapic_send_ipi(0, dest_lapic_id, 5);
}

void lapic_send_startup(uint32_t dest_lapic_id, uint8_t vector) {
    // Mode 6 = STARTUP, Level Assert
    lapic_send_ipi(vector, dest_lapic_id, 6);
}

void lapic_send_nmi(uint32_t dest_lapic_id) {
    // Mode 4 = NMI
    lapic_send_ipi(0, dest_lapic_id, 4);
}

static uint32_t try_cpuid_frequency(void) {
    cpuid_registers_t regs = cpu_read_value(CPUID_TIME_INFO);

    if (regs.ecx == 0 || regs.eax == 0 || regs.ebx == 0) {
        return 0;
    }

    return regs.ecx;
}

static uint32_t calibrate_manually(void) {
    const size_t calibration_ms = 50;

    lapic_write(LAPIC_REG_DIVIDE_CONF, TIMER_DIV_16);
    lapic_write(LAPIC_REG_LVT_TIMER, LVT_MASKED);
    lapic_write(LAPIC_REG_INIT_COUNT, UINT32_MAX);

    timer_mdelay(calibration_ms);

    uint32_t curr = lapic_read(LAPIC_REG_CURRENT_COUNT);
    lapic_write(LAPIC_REG_INIT_COUNT, 0);

    uint32_t ticks         = UINT32_MAX - curr;
    uint64_t ticks_per_sec = (uint64_t)ticks * (1000 / calibration_ms) * 16;

    return (uint32_t)ticks_per_sec;
}

void lapic_timer_calibrate(void) {
    freq_hz = try_cpuid_frequency();

    if (freq_hz == 0) {
        freq_hz = calibrate_manually();
    }

    if (freq_hz == 0) {
        if (!warned_no_freq) {
            warned_no_freq = true;
            KLOG_WARN("LAPIC: timer calibration failed (freq_hz=0)\n");
        }

        return;
    }

    ticks_per_us = (freq_hz / 16) / 1000000;
    if (ticks_per_us == 0) {
        ticks_per_us = 1;
    }

    KLOG_INFO("LAPIC: timer calibrated freq=%u Hz ticks_per_us=%u\n", freq_hz, ticks_per_us);
}

void lapic_timer_mask(void) {
    lapic_write(LAPIC_REG_LVT_TIMER, lapic_read(LAPIC_REG_LVT_TIMER) | LVT_MASKED);
}

void lapic_timer_unmask(void) {
    lapic_write(LAPIC_REG_LVT_TIMER, lapic_read(LAPIC_REG_LVT_TIMER) & ~LVT_MASKED);
}

void lapic_timer_stop(void) {
    lapic_write(LAPIC_REG_INIT_COUNT, 0);

    if (tsc_deadline_supported) {
        write_msr(X86_MSR_IA32_TSC_DEADLINE, 0);
    }
}

void lapic_timer_start(size_t ticks) {
    if (tsc_deadline_supported && (lapic_read(LAPIC_REG_LVT_TIMER) & LVT_TIMER_MODE_TSC_DEADLINE)) {
        write_msr(X86_MSR_IA32_TSC_DEADLINE, ticks);
    } else {
        lapic_write(LAPIC_REG_INIT_COUNT, (uint32_t)(ticks * ticks_per_us));
    }
}

void lapic_configure_timer(timer_mode_t mode, uint8_t vector, uint64_t count) {
    if (mode != TIMER_TSC_DEADLINE && ticks_per_us == 0) {
        return;
    }

    lapic_timer_stop();

    uint32_t lvt = vector;
    if (mode == TIMER_PERIODIC) {
        lvt |= LVT_TIMER_MODE_PERIODIC;
    } else if (mode == TIMER_TSC_DEADLINE && tsc_deadline_supported) {
        lvt |= LVT_TIMER_MODE_TSC_DEADLINE;
    } else {
        lvt |= LVT_TIMER_MODE_ONESHOT;
    }

    lapic_write(LAPIC_REG_LVT_TIMER, lvt);
    lapic_write(LAPIC_REG_DIVIDE_CONF, TIMER_DIV_16);
    curr_mode = mode;

    if (mode == TIMER_TSC_DEADLINE && tsc_deadline_supported) {
        asm volatile("mfence" ::: "memory");
        write_msr(X86_MSR_IA32_TSC_DEADLINE, count);
    } else {
        uint32_t ticks = (uint32_t)(count * ticks_per_us);
        lapic_write(LAPIC_REG_INIT_COUNT, ticks ? ticks : 1);
    }
}