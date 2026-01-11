#include "drivers/hpet.h"

#include <errno.h>
#include <stdint.h>
#include <uacpi/acpi.h>
#include <uacpi/tables.h>

#include "arch.h"
#include "drivers/arch_timer.h"
#include "drivers/pit.h"
#include "drivers/timer.h"
#include "libs/log.h"
#include "memory/memory.h"
#include "memory/pagemap.h"
#include "memory/vma.h"
#include "memory/vmm.h"

#define FEMTOSECONDS_PER_NS 1000000ul
#define FEMTOSECONDS_PER_US 1000000000ul
#define FEMTOSECONDS_PER_MS 1000000000000ul

// General Capabilities (Offset 0x00)
#define HPET_CAP_REV_ID      (0xfful << 0)
#define HPET_CAP_NUM_TIM_CAP (0x1ful << 8)
#define HPET_CAP_COUNT_SIZE  (1ul << 13)
#define HPET_CAP_COUNTER_CLK (0xffffffff00000000ul)  // Period in femptoseconds

// General Configuration (Offset 0x10)
#define HPET_CONF_ENABLE (1ul << 0)
#define HPET_CONF_LEGACY (1ul << 1)

// Timer Configuration and Capabilities (Offset 0x100 + 0x20n)
#define TN_INT_TYPE_CNF    (1ul << 1)  // 0=Edge, 1=Level
#define TN_INT_ENB_CNF     (1ul << 2)
#define TN_TYPE_CNF        (1ul << 3)     // 0=Non-periodic, 1=Periodic
#define TN_PER_INT_CAP     (1ul << 4)     // Periodic capable
#define TN_SIZE_CAP        (1ul << 5)     // 64-bit capable
#define TN_VAL_SET_CNF     (1ul << 6)     // Allow setting accumulator
#define TN_32MODE_CNF      (1ul << 8)     // Force 32-bit mode
#define TN_INT_ROUTE_CNF   (0x1ful << 9)  // Routing bits
#define TN_FSB_EN_CNF      (1ul << 14)    // FSB Interrupt Enable
#define TN_FSB_INT_DEL_CAP (1ul << 15)    // FSB Delivery Capable

typedef struct {
    volatile uint64_t conf_caps;
    volatile uint64_t comparator_value;
    volatile uint64_t fsb_int_route;
    uint64_t reserved;
} hpet_timer_register_t;

typedef struct {
    volatile uint64_t general_caps;
    uint64_t reserved0;
    volatile uint64_t general_config;
    uint64_t reserved1;
    volatile uint64_t general_int_status;
    uint8_t reserved2[0xf0 - 0x28];
    volatile uint64_t main_counter_value;
    uint64_t reserved3;
    hpet_timer_register_t timers[];
} hpet_register_t;

static hpet_register_t* hpet_regs = nullptr;
static uint64_t clock_period_fs   = 0;

static bool warned_no_clock_period = false;
static bool warned_no_hpet_regs    = false;

void hpet_init(void) {
    uacpi_table hpet_view;

    if (hpet_regs) {
        errno = EAGAIN;
        KLOG_DEBUG("HPET: already initialized\n");
        return;
    }

    if (uacpi_table_find_by_signature(ACPI_HPET_SIGNATURE, &hpet_view) != UACPI_STATUS_OK) {
        errno = ENODEV;
        KLOG_WARN("HPET: ACPI table not found\n");
        return;
    }

    struct acpi_hpet* hpet = (struct acpi_hpet*)hpet_view.ptr;

    if (hpet->address.address_space_id != UACPI_ADDRESS_SPACE_SYSTEM_MEMORY) {
        errno = ENODEV;
        KLOG_WARN("HPET: unsupported address space id=%u\n", hpet->address.address_space_id);
        uacpi_table_unref(&hpet_view);
        return;
    }

    uintptr_t phys_addr = hpet->address.address;
    uacpi_table_unref(&hpet_view);

    size_t size = PAGE_SIZE_SMALL;

    hpet_regs = vmm_alloc(&kernel_space, size, VMM_FLAG_MMIO, CACHE_MMIO, PAGE_SIZE_SMALL);

    pagemap_map_args_t args = {
        .virt_addr = hpet_regs,
        .phys_addr = (void*)phys_addr,
        .length    = PAGE_SIZE_SMALL,
        .flags     = VMM_FLAG_READ | VMM_FLAG_WRITE | VMM_FLAG_GLOBAL,
        .cache     = CACHE_MMIO,
        .page_size = PAGE_SIZE_SMALL
    };

    pagemap_t* map = vmm_get_kernel_pagemap();

    if (!pagemap_map(map, args)) {
        PANIC("Failed to map HPET's virtual base");
        return;
    }

    uint64_t caps           = hpet_regs->general_caps;
    uint64_t tick_period_fs = caps >> 32;
    bool has_64bit_count    = caps & TN_SIZE_CAP;
    uint16_t vendor_id      = (caps >> 16) & 0xffff;

    // n_timers = (bits 8:12 of cap) + 1
    size_t num_timers = ((hpet_regs->general_caps >> 8) & 0x1f) + 1;

    if (vendor_id == 0 || vendor_id == 0xffff) {
        errno = ENODEV;
        KLOG_WARN("HPET: invalid vendor id=0x%04x\n", vendor_id);
        return;
    }

    if (tick_period_fs == 0) {
        errno = EINVAL;
        KLOG_WARN("HPET: reported zero tick period\n");
        return;
    }

    clock_period_fs = tick_period_fs;

    hpet_regs->general_config &= ~HPET_CONF_LEGACY;
    hpet_regs->general_config |= HPET_CONF_ENABLE;

    KLOG_INFO(
        "HPET: enabled (%u timers, %s counter, period=%llu fs)\n",
        num_timers,
        has_64bit_count ? "64-bit" : "32-bit",
        tick_period_fs
    );

    timer_set_clock_source(CLOCK_HPET);
    pit_disable();
}

void hpet_disable(void) {
    hpet_regs->general_config &= ~HPET_CONF_ENABLE;
}

static uint64_t time_to_ticks(uint64_t value, uint64_t fs_per_unit) {
    // Total FS = value * fs_per_unit
    // Ticks = Total FS / clock_period_fs
    if (clock_period_fs == 0) {
        errno = ENODEV;

        if (!warned_no_clock_period) {
            warned_no_clock_period = true;
            KLOG_WARN("HPET: clock period is zero; initialize HPET first\n");
        }

        return 0;
    }

    return (value * fs_per_unit) / clock_period_fs;
}

void hpet_ndelay(size_t ns) {
    if (!hpet_regs) {
        errno = ENODEV;

        if (!warned_no_hpet_regs) {
            warned_no_hpet_regs = true;
            KLOG_WARN("HPET: ndelay requested before initialization\n");
        }

        return;
    }

    size_t start = hpet_regs->main_counter_value;
    size_t ticks = time_to_ticks(ns, FEMTOSECONDS_PER_NS);

    if (ticks == 0) {
        return;
    }

    while (hpet_regs->main_counter_value < (start + ticks)) {
        arch_pause();
    }
}

void hpet_udelay(size_t us) {
    if (!hpet_regs) {
        errno = ENODEV;

        if (!warned_no_hpet_regs) {
            warned_no_hpet_regs = true;
            KLOG_WARN("HPET: udelay requested before initialization\n");
        }

        return;
    }

    size_t start = hpet_regs->main_counter_value;
    size_t ticks = time_to_ticks(us, FEMTOSECONDS_PER_US);

    if (ticks == 0) {
        return;
    }

    while (hpet_regs->main_counter_value < (start + ticks)) {
        arch_pause();
    }
}

void hpet_mdelay(size_t ms) {
    if (!hpet_regs) {
        errno = ENODEV;

        if (!warned_no_hpet_regs) {
            warned_no_hpet_regs = true;
            KLOG_WARN("HPET: mdelay requested before initialization\n");
        }

        return;
    }

    size_t start = hpet_regs->main_counter_value;
    size_t ticks = time_to_ticks(ms, FEMTOSECONDS_PER_MS);

    if (ticks == 0) {
        return;
    }

    while (hpet_regs->main_counter_value < (start + ticks)) {
        arch_pause();
    }
}

size_t hpet_get_ticks(void) {
    return hpet_regs->main_counter_value / clock_period_fs;
}

size_t hpet_get_hz(void) {
    return clock_period_fs;
}