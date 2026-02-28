#include "cpu/lapic.h"

#include <errno.h>
#include <llvm-libc-macros/generic-error-number-macros.h>
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

static void* virt_base = nullptr;

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

    uintptr_t addr = (uintptr_t)virt_base + offset;
    return mmio_read32((void*)addr);
}

static void lapic_write(size_t offset, uint32_t val) {
    if (x2apic_enabled) {
        write_msr(LAPIC_X2APIC_MSR_BASE + (offset >> 4), val);
    } else {
        uintptr_t addr = (uintptr_t)virt_base + offset;
        mmio_write32((void*)addr, val);
    }
}

static void apic_error_handler(interrupt_trapframe_t*, void*) {
    const size_t buf_size = 512;
    char buf[buf_size];
    size_t offset = 0;

    // APIC requires a write before error status can be read.
    lapic_write(LAPIC_REG_ERROR_STATUS, 0);
    uint32_t error_flags = lapic_read(LAPIC_REG_ERROR_STATUS);

    if (!error_flags) {
        return;
    }

    offset += (size_t)snprintf(
        buf + offset,
        buf_size + offset,
        "\n[APIC ERROR] CPU %d ESR: 0x%08lx | Flags: ",
        arch_get_core_idx(),
        error_flags
    );

    if (error_flags & LAPIC_ERR_SEND_CS_ERROR) {
        offset += (size_t)snprintf(buf + offset, buf_size - offset, " [Send Checksum] ");
    }

    if (error_flags & LAPIC_ERR_RECV_CS_ERROR) {
        offset += (size_t)snprintf(buf + offset, buf_size - offset, " [Recv Checksum] ");
    }

    if (error_flags & LAPIC_ERR_SEND_ACCEPT_ERROR) {
        offset += (size_t)snprintf(buf + offset, buf_size - offset, " [Send Accept] ");
    }

    if (error_flags & LAPIC_ERR_RECV_ACCEPT_ERROR) {
        offset += (size_t)snprintf(buf + offset, buf_size - offset, " [Recv Accept] ");
    }

    if (error_flags & LAPIC_ERR_REDIRECTABLE_IPI) {
        offset += (size_t)snprintf(buf + offset, buf_size - offset, " [Redirectable IPI] ");
    }

    if (error_flags & LAPIC_ERR_SEND_ILLEGAL_VECTOR) {
        offset += (size_t)snprintf(buf + offset, buf_size - offset, " [Send Illegal Vec] ");
    }

    if (error_flags & LAPIC_ERR_RECV_ILLEGAL_VECTOR) {
        offset += (size_t)snprintf(buf + offset, buf_size - offset, " [Recv Illegal Vec] ");
    }

    if (error_flags & LAPIC_ERR_ILLEGAL_REGISTER) {
        offset += (size_t)snprintf(buf + offset, buf_size - offset, " [Illegal Reg Access] ");
    }

    if (offset < buf_size - 1) {
        buf[offset++] = '\n';
        buf[offset]   = '\0';
    }

    KLOG_ERROR("%s", buf);
}

static void apic_timer_handler(interrupt_trapframe_t*, void*) {
    timer_tick();
}

static inline void lapic_error_init(void) {
    lapic_write(LAPIC_REG_LVT_ERROR, LVT_VECTOR(INTERRUPT_APIC_ERROR));
    lapic_write(LAPIC_REG_ERROR_STATUS, 0);
}

static inline void lapic_pmi_init(void) {
    lapic_write(LAPIC_REG_LVT_PERF, LVT_VECTOR(INTERRUPT_APIC_PMI) | LVT_MASKED);
}

static inline void lapic_timer_init(void) {
    uint32_t val = LVT_VECTOR(INTERRUPT_APIC_TIMER) | LVT_MASKED;

    if (tsc_deadline_supported) {
        val &= ~LVT_MASKED;
        val |= LVT_TIMER_MODE_TSC_DEADLINE;

        asm volatile("mfence" ::: "memory");
    }

    lapic_write(LAPIC_REG_LVT_TIMER, val);
}

void lapic_init(void) {
    tsc_deadline_supported = cpu_has_feature(FEATURE_TSC_DEADLINE);

    uint64_t apic_base_msr  = read_msr(X86_MSR_IA32_APIC_BASE);
    bool is_bsp             = (apic_base_msr & IA32_APIC_BASE_BSP) != 0;
    bool has_x2apic_support = cpu_has_feature(FEATURE_X2APIC);

    KLOG_DEBUG(
        "LAPIC: init start bsp=%d has_x2apic=%d tsc_deadline=%d\n",
        is_bsp,
        has_x2apic_support,
        tsc_deadline_supported
    );

    if (is_bsp && has_x2apic_support) {
        x2apic_enabled = true;
    }

    if (!x2apic_enabled && !virt_base) {
        uintptr_t phys_base = apic_base_msr & X86_PAGE_ADDRESS_MASK;
        size_t size         = PAGE_SIZE_SMALL;

        virt_base =
            vmalloc(kernel_space, nullptr, size, VMM_FLAG_MMIO, CACHE_MMIO, PAGE_SIZE_SMALL);

        if (!virt_base) {
            errno = ENOMEM;
            PANIC(
                "LAPIC: failed to allocate MMIO page size=0x%lx errno=%d\n",
                PAGE_SIZE_SMALL,
                errno
            );
        }

        pagemap_map_args_t args = {
            .virt_addr = virt_base,
            .phys_addr = (void*)phys_base,
            .length    = PAGE_SIZE_SMALL,
            .flags     = VMM_FLAG_READ | VMM_FLAG_WRITE | VMM_FLAG_GLOBAL,
            .cache     = CACHE_MMIO,
            .page_size = PAGE_SIZE_SMALL
        };

        pagemap_t* map = vmm_get_kernel_pagemap();

        if (!pagemap_map(map, &args)) {
            PANIC(
                "LAPIC: failed to map MMIO base=0x%lx -> %p errno=%d\n",
                phys_base,
                virt_base,
                errno
            );
        }

        KLOG_DEBUG(
            "LAPIC: mapped MMIO base=0x%lx -> %p cache=%d flags=0x%x\n",
            phys_base,
            virt_base,
            CACHE_MMIO,
            VMM_FLAG_READ | VMM_FLAG_WRITE | VMM_FLAG_GLOBAL
        );
    }

    apic_base_msr |= IA32_APIC_BASE_X2APIC_ENABLE;
    apic_base_msr |= x2apic_enabled ? IA32_APIC_BASE_X2APIC_ENABLE : 0;

    write_msr(X86_MSR_IA32_APIC_BASE, apic_base_msr);

    uint32_t svr = SVR_SPURIOUS_VECTOR(INTERRUPT_APIC_SPURIOUS) | SVR_APIC_ENABLE;
    lapic_write(LAPIC_REG_SPURIOUS_IRQ, svr);
    lapic_write(LAPIC_REG_TASK_PRIORITY, 0);

    lapic_error_init();
    lapic_pmi_init();
    lapic_timer_init();

    create_interrupt_lock(&lock);

    int res = register_interrupt_handler(
        INTERRUPT_APIC_TIMER,
        apic_timer_handler,
        nullptr,
        IRQ_TRIGGER_EDGE,
        IRQ_POLARITY_HIGH
    );

    if (res != 0) {
        int err = errno ? errno : EIO;
        PANIC("LAPIC: failed to register timer handler errno=%d\n", err);
    }

    res = register_interrupt_handler(
        INTERRUPT_APIC_ERROR,
        apic_error_handler,
        nullptr,
        IRQ_TRIGGER_EDGE,
        IRQ_POLARITY_HIGH
    );

    if (res != 0) {
        int err = errno ? errno : EIO;
        PANIC("LAPIC: failed to register error handler errno=%d\n", err);
    }

    KLOG_INFO(
        "LAPIC: initialized mode=%s phys=0x%lx virt=%p tsc_deadline=%d x2apic=%d\n",
        x2apic_enabled ? "x2APIC" : "xAPIC",
        apic_base_msr & X86_PAGE_ADDRESS_MASK,
        virt_base,
        tsc_deadline_supported,
        x2apic_enabled
    );
}

uint32_t lapic_local_id(void) {
    uint32_t id = lapic_read(LAPIC_REG_ID);

    // Legacy LAPIC stores the id in the top 8 bits of the register
    if (!x2apic_enabled) {
        id >>= 24;
    }

    return id;
}

static inline void lapic_wait_for_ipi_send(void) {
    while (lapic_read(LAPIC_REG_IRQ_CMD_LOW) & ICR_DELIVERY_PENDING) {
        arch_pause();
    }
}

void lapic_send_ipi(uint8_t vector, uint32_t dest_lapic_id, apic_interrupt_delivery_mode_t mode) {
    uint32_t req = ICR_LEVEL_ASSERT | ICR_DELIVERY_MODE(mode) | ICR_VECTOR(vector);

    if (x2apic_enabled) {
        write_msr(LAPIC_X2APIC_MSR_ICR, X2_ICR_DST(dest_lapic_id) | req);
        return;
    }

    acquire_interrupt_lock(&lock);

    lapic_write(LAPIC_REG_IRQ_CMD_HIGH, ICR_DST(dest_lapic_id));
    lapic_write(LAPIC_REG_IRQ_CMD_LOW, req);
    lapic_wait_for_ipi_send();

    release_interrupt_lock(&lock);
}

void lapic_send_self_ipi(uint8_t vector, apic_interrupt_delivery_mode_t mode) {
    uint32_t req = ICR_LEVEL_ASSERT | ICR_DELIVERY_MODE(mode) | ICR_VECTOR(vector) | ICR_DST_SELF;

    if (x2apic_enabled) {
        write_msr(LAPIC_X2APIC_MSR_SELF_IPI, vector);
        return;
    }

    acquire_interrupt_lock(&lock);

    lapic_write(LAPIC_REG_IRQ_CMD_LOW, req);
    lapic_wait_for_ipi_send();

    release_interrupt_lock(&lock);
}

void lapic_send_broadcast_self_ipi(uint8_t vector, apic_interrupt_delivery_mode_t mode) {
    uint32_t req = ICR_LEVEL_ASSERT | ICR_DELIVERY_MODE(mode) | ICR_VECTOR(vector) | ICR_DST_ALL;

    if (x2apic_enabled) {
        write_msr(LAPIC_X2APIC_MSR_ICR, X2_ICR_BROADCAST | req);
        return;
    }

    acquire_interrupt_lock(&lock);

    lapic_write(LAPIC_REG_IRQ_CMD_HIGH, ICR_DST_BROADCAST);
    lapic_write(LAPIC_REG_IRQ_CMD_LOW, req);
    lapic_wait_for_ipi_send();

    release_interrupt_lock(&lock);
}

void lapic_send_broadcast_ipi(uint8_t vector, apic_interrupt_delivery_mode_t mode) {
    uint32_t req = ICR_LEVEL_ASSERT | ICR_DELIVERY_MODE(mode) | ICR_VECTOR(vector);
    req |= ICR_DST_ALL_MINUS_SELF;

    if (x2apic_enabled) {
        write_msr(LAPIC_X2APIC_MSR_ICR, X2_ICR_BROADCAST | req);
        return;
    }

    acquire_interrupt_lock(&lock);

    lapic_write(LAPIC_REG_IRQ_CMD_HIGH, ICR_DST_BROADCAST);
    lapic_write(LAPIC_REG_IRQ_CMD_LOW, req);
    lapic_wait_for_ipi_send();

    release_interrupt_lock(&lock);
}

void lapic_send_eoi(void) {
    lapic_write(LAPIC_REG_EOI, 0);
}

void lapic_timer_mask(void) {
    uint32_t val = lapic_read(LAPIC_REG_LVT_TIMER);
    lapic_write(LAPIC_REG_LVT_TIMER, val | LVT_MASKED);
}

void lapic_timer_unmask(void) {
    uint32_t val = lapic_read(LAPIC_REG_LVT_TIMER);
    lapic_write(LAPIC_REG_LVT_TIMER, val & ~LVT_MASKED);
}

void lapic_timer_stop(void) {
    lapic_write(LAPIC_REG_INIT_COUNT, 0);

    if (tsc_deadline_supported) {
        write_msr(X86_MSR_IA32_TSC_DEADLINE, 0);
    }
}

void lapic_timer_start(size_t ticks) {
    uint32_t is_tsc = lapic_read(LAPIC_REG_LVT_TIMER) & LVT_TIMER_MODE_TSC_DEADLINE;

    if (tsc_deadline_supported && is_tsc) {
        write_msr(X86_MSR_IA32_TSC_DEADLINE, ticks);
    } else {
        uint32_t count = (uint32_t)(ticks * ticks_per_us);
        lapic_write(LAPIC_REG_INIT_COUNT, count);
    }
}

static uint32_t try_cpuid_frequency(void) {
    cpuid_registers_t regs = cpu_read_value(CPUID_TIME_INFO);

    if (regs.ecx == 0 || regs.eax == 0 || regs.ebx == 0) {
        return 0;
    }

    return regs.ecx;
}

static uint32_t calibrate_manually(void) {
    lapic_write(LAPIC_REG_DIVIDE_CONF, TIMER_DIV_16);
    lapic_write(LAPIC_REG_LVT_TIMER, LVT_MASKED);
    lapic_write(LAPIC_REG_INIT_COUNT, UINT32_MAX);

    const size_t calibaration_ms = 50;
    timer_mdelay(calibaration_ms);

    uint32_t curr = lapic_read(LAPIC_REG_CURRENT_COUNT);
    lapic_write(LAPIC_REG_INIT_COUNT, 0);

    uint64_t ticks = UINT32_MAX - curr;

    return (uint32_t)(ticks * 100 * 16);
}

void lapic_timer_calibrate(void) {
    freq_hz = try_cpuid_frequency();

    if (freq_hz == 0) {
        freq_hz = calibrate_manually();
    }

    if (freq_hz == 0) {
        errno = EIO;

        if (!warned_no_freq) {
            warned_no_freq = true;
            KLOG_WARN("LAPIC: timer calibration failed (freq_hz=0)\n");
        }

        return;
    }

    ticks_per_us = (freq_hz / 16) / 1000000;

    if (ticks_per_us == 0) {
        ticks_per_us = 1;
        errno        = ERANGE;
        KLOG_WARN("LAPIC: ticks_per_us underflow, clamping to 1\n");
    }

    KLOG_INFO("LAPIC: timer calibrated freq=%u Hz ticks_per_us=%u\n", freq_hz, ticks_per_us);
}

static void set_lvt_mode(uint8_t vector, timer_mode_t mode) {
    lapic_write(LAPIC_REG_LVT_TIMER, 0);

    if (curr_mode == TIMER_TSC_DEADLINE) {
        write_msr(X86_MSR_IA32_TSC_DEADLINE, 0);
    }

    uint32_t lvt = vector;

    switch (mode) {
        case TIMER_ONESHOT:
            lvt |= LVT_TIMER_MODE_ONESHOT;
            break;
        case TIMER_PERIODIC:
            lvt |= LVT_TIMER_MODE_PERIODIC;
            break;
        case TIMER_TSC_DEADLINE:
            if (tsc_deadline_supported) {
                lvt |= LVT_TIMER_MODE_TSC_DEADLINE;
            } else {
                errno = ENODEV;

                if (!warned_deadline_mode) {
                    warned_deadline_mode = true;
                    KLOG_WARN(
                        "LAPIC: TSC deadline mode requested but not supported; falling back to "
                        "one-shot\n"
                    );
                }

                lvt |= LVT_TIMER_MODE_ONESHOT;
            }
            break;
    }

    lapic_write(LAPIC_REG_LVT_TIMER, lvt);
    lapic_write(LAPIC_REG_DIVIDE_CONF, TIMER_DIV_16);

    curr_mode = mode;
}

void lapic_configure_timer(timer_mode_t mode, uint8_t vector, uint64_t count) {
    if (mode != TIMER_TSC_DEADLINE && ticks_per_us == 0) {
        errno = ENODEV;

        if (!warned_no_freq) {
            warned_no_freq = true;
            KLOG_WARN("LAPIC: configure_timer called before calibration\n");
        }

        return;
    }

    set_lvt_mode(vector, mode);

    if (mode == TIMER_TSC_DEADLINE) {
        asm volatile("mfence" ::: "memory");
        write_msr(X86_MSR_IA32_TSC_DEADLINE, count);
    } else {
        uint32_t ticks = (uint32_t)(count * ticks_per_us);

        if (ticks == 0 && count > 0) {
            ticks = 1;
        }

        lapic_write(LAPIC_REG_INIT_COUNT, ticks);
    }
}