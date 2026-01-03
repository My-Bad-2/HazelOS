#include "cpu/lapic.h"

#include <errno.h>
#include <stdio.h>

#include "arch.h"
#include "cpu/cpu.h"
#include "cpu/exception.h"
#include "cpu/registers.h"
#include "libs/log.h"
#include "libs/mmio.h"
#include "libs/spinlock.h"
#include "memory/memory.h"
#include "memory/pagemap.h"
#include "memory/paging.h"
#include "memory/vma.h"
#include "memory/vmm.h"

#include "internal/lapic.h"

static void* lapic_virt_base       = nullptr;
static bool x2apic_enabled         = false;
static bool tsc_deadline_supported = false;
static interrupt_lock_t lock;

static uint32_t lapic_read(size_t offset) {
    if (x2apic_enabled) {
        return (uint32_t)read_msr(LAPIC_X2APIC_MSR_BASE + (offset >> 4));
    }

    uintptr_t addr = (uintptr_t)lapic_virt_base + offset;
    return mmio_read32((void*)addr);
}

static void lapic_write(size_t offset, uint32_t val) {
    if (x2apic_enabled) {
        write_msr(LAPIC_X2APIC_MSR_BASE + (offset >> 4), val);
    } else {
        uintptr_t addr = (uintptr_t)lapic_virt_base + offset;
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
        "[APIC ERROR] CPU %d ESR: 0x%08lx | Flags: ",
        arch_get_core_idx(),
        error_flags
    );

    if (error_flags & APIC_ERR_SEND_CS_ERROR) {
        offset += (size_t)snprintf(buf + offset, buf_size - offset, " [Send Checksum] ");
    }

    if (error_flags & APIC_ERR_RECV_CS_ERROR) {
        offset += (size_t)snprintf(buf + offset, buf_size - offset, " [Recv Checksum] ");
    }

    if (error_flags & APIC_ERR_SEND_ACCEPT_ERROR) {
        offset += (size_t)snprintf(buf + offset, buf_size - offset, " [Send Accept] ");
    }

    if (error_flags & APIC_ERR_RECV_ACCEPT_ERROR) {
        offset += (size_t)snprintf(buf + offset, buf_size - offset, " [Recv Accept] ");
    }

    if (error_flags & APIC_ERR_REDIRECTABLE_IPI) {
        offset += (size_t)snprintf(buf + offset, buf_size - offset, " [Redirectable IPI] ");
    }

    if (error_flags & APIC_ERR_SEND_ILLEGAL_VECTOR) {
        offset += (size_t)snprintf(buf + offset, buf_size - offset, " [Send Illegal Vec] ");
    }

    if (error_flags & APIC_ERR_RECV_ILLEGAL_VECTOR) {
        offset += (size_t)snprintf(buf + offset, buf_size - offset, " [Recv Illegal Vec] ");
    }

    if (error_flags & APIC_ERR_ILLEGAL_REGISTER) {
        offset += (size_t)snprintf(buf + offset, buf_size - offset, " [Illegal Reg Access] ");
    }

    if (offset < buf_size - 1) {
        buf[offset++] = '\n';
        buf[offset]   = '\0';
    }

    KLOG_ERROR("%s", buf);
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

    if (!x2apic_enabled && !lapic_virt_base) {
        uintptr_t phys_base = apic_base_msr & X86_PAGE_ADDRESS_MASK;

        lapic_virt_base =
            vmm_alloc(&kernel_space, PAGE_SIZE_SMALL, VMM_FLAG_MMIO, CACHE_MMIO, PAGE_SIZE_SMALL);

        if (!lapic_virt_base) {
            errno = ENOMEM;
            PANIC(
                "LAPIC: failed to allocate MMIO page size=0x%lx errno=%d\n",
                PAGE_SIZE_SMALL,
                errno
            );
        }

        pagemap_map_args_t args = {
            .virt_addr = lapic_virt_base,
            .phys_addr = (void*)phys_base,
            .length    = PAGE_SIZE_SMALL,
            .flags     = VMM_FLAG_READ | VMM_FLAG_WRITE | VMM_FLAG_GLOBAL,
            .cache     = CACHE_MMIO,
            .page_size = PAGE_SIZE_SMALL
        };

        pagemap_t* map = vmm_get_kernel_pagemap();

        if (!pagemap_map(map, args)) {
            PANIC(
                "LAPIC: failed to map MMIO base=0x%lx -> %p errno=%d\n",
                phys_base,
                lapic_virt_base,
                errno
            );
        }

        KLOG_DEBUG(
            "LAPIC: mapped MMIO base=0x%lx -> %p cache=%d flags=0x%x\n",
            phys_base,
            lapic_virt_base,
            CACHE_MMIO,
            VMM_FLAG_READ | VMM_FLAG_WRITE | VMM_FLAG_GLOBAL
        );
    }

    apic_base_msr |= IA32_APIC_BASE_X2APIC_ENABLE;
    apic_base_msr |= x2apic_enabled ? IA32_APIC_BASE_X2APIC_ENABLE : 0;

    write_msr(X86_MSR_IA32_APIC_BASE, apic_base_msr);

    uint32_t svr = SVR_SPURIOUS_VECTOR(INTERRUPT_APIC_SPURIOUS) | SVR_APIC_ENABLE;
    lapic_write(LAPIC_REG_SPURIOUS_IRQ, svr);

    lapic_error_init();
    lapic_pmi_init();
    lapic_timer_init();

    create_interrupt_lock(&lock);

    int res = register_interrupt_handler(
        INTERRUPT_APIC_ERROR,
        1,
        apic_error_handler,
        nullptr,
        IRQ_TRIGGER_EDGE,
        IRQ_POLARITY_HIGH
    );

    if (res != 0) {
        int err = errno ? errno : EIO;
        PANIC("LAPIC: failed to register error handler errno=%d\n", err);
    }

    KLOG_DEBUG(
        "LAPIC: initialized mode=%s phys=0x%lx virt=%p tsc_deadline=%d x2apic=%d\n",
        x2apic_enabled ? "x2APIC" : "xAPIC",
        apic_base_msr & X86_PAGE_ADDRESS_MASK,
        lapic_virt_base,
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

void lapic_send_ipi(uint8_t vector, uint32_t dest_lapic_id, lapic_interrupt_delivery_mode_t mode) {
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

void lapic_send_self_ipi(uint8_t vector, lapic_interrupt_delivery_mode_t mode) {
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

void lapic_send_broadcast_self_ipi(uint8_t vector, lapic_interrupt_delivery_mode_t mode) {
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

void lapic_send_broadcast_ipi(uint8_t vector, lapic_interrupt_delivery_mode_t mode) {
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