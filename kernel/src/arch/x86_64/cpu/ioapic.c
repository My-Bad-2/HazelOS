#include "cpu/ioapic.h"

#include <stdint.h>
#include <uacpi/acpi.h>

#include "cpu/exception.h"
#include "cpu/io.h"
#include "drivers/madt.h"
#include "libs/log.h"
#include "libs/math.h"
#include "libs/mmio.h"
#include "libs/spinlock.h"
#include "memory/heap.h"
#include "memory/memory.h"
#include "memory/pagemap.h"
#include "memory/vm_object.h"
#include "memory/vma.h"
#include "memory/vmm.h"

#include "internal/ioapic.h"

#define NUM_IRQS               16
#define PORT_ADDRESS           0x22
#define PORT_DATA              0x23
#define IMCR_PORT_ADDRESS      0x70
#define IMCR_PASS_THROUGH_APIC 0x01

typedef struct {
    struct acpi_madt_ioapic desc;
    uint8_t version;
    uint8_t max_redirection_entry;
    void* virt_base;
} ioapic_t;

static size_t ioapic_count = 0;
static ioapic_t* ioapics   = nullptr;

static struct iso_override {
    uint8_t irq;
    bool remapped;
    irq_trigger_mode_t trigger;
    irq_polarity_t polarity;
    uint32_t gsi;
} overrides[NUM_IRQS];

static qspinlock_t lock;

// https://pdos.csail.mit.edu/6.828/2008/readings/ia32/MPspec.pdf Pg 3-8
static inline void imcr_connect_to_ioapic(void) {
    io_write8(PORT_ADDRESS, IMCR_PORT_ADDRESS);
    io_write8(PORT_DATA, IMCR_PASS_THROUGH_APIC);
}

static inline uint32_t ioapic_read(ioapic_t* ioapic, uint8_t reg) {
    mmio_write32((void*)((uintptr_t)ioapic->virt_base + IOAPIC_IOREGSEL), reg);
    return mmio_read32((void*)((uintptr_t)ioapic->virt_base + IOAPIC_IOWIN));
}

static inline void ioapic_write(ioapic_t* ioapic, uint8_t reg, uint32_t val) {
    mmio_write32((void*)((uintptr_t)ioapic->virt_base + IOAPIC_IOREGSEL), reg);
    mmio_write32((void*)((uintptr_t)ioapic->virt_base + IOAPIC_IOWIN), val);
}

static ioapic_rte_t ioapic_read_rte(ioapic_t* ioapic, uint32_t gsi) {
    uint32_t offset = gsi - ioapic->desc.gsi_base;
    uint8_t reg     = (uint8_t)IOAPIC_REG_RTE(offset);

    ioapic_rte_t rte;
    rte.low  = ioapic_read(ioapic, reg);
    rte.high = ioapic_read(ioapic, reg + 1);
    return rte;
}

static void ioapic_write_rte(ioapic_t* ioapic, uint32_t gsi, ioapic_rte_t rte) {
    uint32_t offset = gsi - ioapic->desc.gsi_base;
    uint8_t reg     = (uint8_t)IOAPIC_REG_RTE(offset);

    ioapic_write(ioapic, reg, rte.low);
    ioapic_write(ioapic, reg + 1, rte.high);
}

static ioapic_t* find_ioapic_for_gsi(uint32_t gsi) {
    for (size_t i = 0; i < ioapic_count; ++i) {
        uint32_t start = ioapics[i].desc.gsi_base;
        uint32_t end   = start + ioapics[i].max_redirection_entry;

        if (start <= gsi && gsi <= end) {
            return &ioapics[i];
        }
    }

    return nullptr;
}

static ioapic_t* require_ioapic(uint32_t gsi) {
    ioapic_t* ioapic = find_ioapic_for_gsi(gsi);
    if (!ioapic) {
        PANIC("IOAPIC: could not resolve global IRQ gsi=%u\n", gsi);
    }

    return ioapic;
}

static void map_ioapic_mmio(ioapic_t* ioapic, size_t index) {
    uintptr_t phys_base = align_down((uintptr_t)ioapic->desc.address, PAGE_SIZE_SMALL);
    void* virt          = nullptr;

    // Check if another IOAPIC shares the same page block to avoid duplicate mappings
    for (size_t i = 0; i < index; ++i) {
        if (align_down(ioapics[i].desc.address, PAGE_SIZE_SMALL) == phys_base) {
            virt = (void*)align_down((uintptr_t)ioapics[i].virt_base, PAGE_SIZE_SMALL);
            break;
        }
    }

    if (!virt) {
        vm_object_t* vmo = vm_object_create(VM_OBJ_PHYSICAL, PAGE_SIZE_SMALL);
        if (!vmo) {
            KLOG_INIT_FAIL();
            PANIC("Failed to allocate vmo!\n");
        }

        virt = vmalloc(
            kernel_space,
            nullptr,
            PAGE_SIZE_SMALL,
            VMM_FLAG_MMIO | VMM_FLAG_DEMAND,
            CACHE_MMIO,
            PAGE_SIZE_SMALL,
            vmo,
            0
        );

        vm_object_deref(vmo);

        if (!virt) {
            KLOG_INIT_FAIL();
            PANIC("IOAPIC: failed to allocate MMIO page for ioapic=%zu", index);
        }

        pagemap_map_args_t args = {
            .virt_addr = virt,
            .phys_addr = (void*)phys_base,
            .length    = PAGE_SIZE_SMALL,
            .flags     = VMM_FLAG_READ | VMM_FLAG_WRITE | VMM_FLAG_GLOBAL,
            .cache     = CACHE_MMIO,
            .page_size = PAGE_SIZE_SMALL
        };

        if (!pagemap_map(vmm_get_kernel_pagemap(), &args)) {
            KLOG_INIT_FAIL();
            PANIC("IOAPIC: failed to map MMIO phys=0x%lx -> %p", phys_base, virt);
        }
    }

    uintptr_t offset  = (uintptr_t)ioapic->desc.address - phys_base;
    ioapic->virt_base = (void*)((uintptr_t)virt + offset);
}

void ioapic_init(void) {
    if (ioapics) {
        return;
    }

    KLOG_INIT_START("IOAPIC");

    ioapic_count = acpi_get_ioapic_count();
    if (ioapic_count == 0) {
        KLOG_INIT_FAIL();
        KLOG_DEBUG("IOAPIC: no IOAPICs detected\n");
        return;
    }

    create_qspinlock(&lock);
    imcr_connect_to_ioapic();

    ioapics = kmalloc(sizeof(ioapic_t) * ioapic_count);
    if (!ioapics) {
        KLOG_INIT_FAIL();
        PANIC("IOAPIC: failed to allocate memory");
    }

    struct acpi_madt_ioapic* descs = acpi_get_ioapics();

    for (size_t i = 0; i < ioapic_count; ++i) {
        ioapics[i].desc = descs[i];
        map_ioapic_mmio(&ioapics[i], i);

        uint32_t ver                     = ioapic_read(&ioapics[i], IOAPIC_REG_VER);
        ioapics[i].version               = IOAPIC_VER_VERSION(ver);
        ioapics[i].max_redirection_entry = IOAPIC_VER_MAX_REDIR_ENTRY(ver);

        for (uint32_t j = 0; j <= ioapics[i].max_redirection_entry; ++j) {
            ioapic_rte_t rte = {.raw = 0};
            rte.mask         = 1;
            ioapic_write_rte(&ioapics[i], j + ioapics[i].desc.gsi_base, rte);
        }
    }

    struct acpi_madt_interrupt_source_override* isos = acpi_get_isos();
    size_t iso_count                                 = acpi_get_iso_count();

    for (size_t i = 0; i < iso_count; i++) {
        struct acpi_madt_interrupt_source_override* iso = &isos[i];

        if (iso->source >= NUM_IRQS || iso->bus != 0) {
            continue;
        }

        struct iso_override* override = &overrides[iso->source];
        override->remapped            = true;
        override->irq                 = iso->source;
        override->gsi                 = iso->gsi;

        uint16_t flags     = iso->flags;
        override->polarity = (flags & ACPI_MADT_POLARITY_MASK) == ACPI_MADT_POLARITY_ACTIVE_LOW
                                 ? IRQ_POLARITY_LOW
                                 : IRQ_POLARITY_HIGH;
        override->trigger  = (flags & ACPI_MADT_TRIGGERING_MASK) == ACPI_MADT_TRIGGERING_LEVEL
                                 ? IRQ_TRIGGER_LEVEL
                                 : IRQ_TRIGGER_EDGE;
    }

    KLOG_INIT_OK();
}

bool ioapic_is_initialized(void) {
    return ioapics != nullptr;
}

bool ioapic_is_valid_irq(uint32_t gsi) {
    return find_ioapic_for_gsi(gsi) != nullptr;
}

uint32_t ioapic_get_gsi(uint8_t irq) {
    return overrides[irq].remapped ? overrides[irq].gsi : irq;
}

void ioapic_mask_irq(uint32_t gsi, bool mask) {
    ioapic_t* ioapic = require_ioapic(gsi);
    size_t flags     = acquire_qinterrupt_lock(&lock);

    ioapic_rte_t rte = ioapic_read_rte(ioapic, gsi);
    rte.mask         = mask ? 1 : 0;
    ioapic_write_rte(ioapic, gsi, rte);

    release_qinterrupt_lock(&lock, flags);
}

void ioapic_send_eoi(uint32_t gsi, uint8_t vector) {
    ioapic_t* ioapic = require_ioapic(gsi);

    // Only IOAPICs >= version 0x20 support the EOIR register.
    if (ioapic->version >= IOAPIC_EOIR_MIN_VERSION) {
        size_t flags = acquire_qinterrupt_lock(&lock);
        mmio_write32((void*)((uintptr_t)ioapic->virt_base + IOAPIC_EOIR_REG), vector);
        release_qinterrupt_lock(&lock, flags);
    }
}

void ioapic_configure_irq(
    uint32_t gsi,
    irq_trigger_mode_t trigger,
    irq_polarity_t polarity,
    apic_interrupt_delivery_mode_t delivery,
    apic_interrupt_dest_mode_t dest,
    uint32_t dest_apic,
    uint8_t vector,
    bool mask
) {
    ioapic_t* ioapic = require_ioapic(gsi);

    if ((delivery == DELIVERY_MODE_FIXED || delivery == DELIVERY_MODE_LOWEST_PRIO) &&
        (vector < PLATFORM_INTERRUPT_BASE || vector > PLATFORM_INTERRUPT_MAX)) {
        mask = true;
    }

    ioapic_rte_t rte  = {.raw = 0};
    rte.vector        = vector;
    rte.delivery_mode = delivery;
    rte.dest_mode     = dest;
    rte.trigger_mode  = trigger;
    rte.polarity      = polarity;
    rte.destination   = dest_apic;
    rte.mask          = mask ? 1 : 0;

    size_t flags = acquire_qinterrupt_lock(&lock);
    ioapic_write_rte(ioapic, gsi, rte);
    release_qinterrupt_lock(&lock, flags);
}

void ioapic_configure_irq_vector(uint32_t gsi, uint8_t vector) {
    ioapic_t* ioapic = require_ioapic(gsi);

    size_t flags     = acquire_qinterrupt_lock(&lock);
    ioapic_rte_t rte = ioapic_read_rte(ioapic, gsi);

    rte.vector = vector;
    if (vector < PLATFORM_INTERRUPT_BASE || vector > PLATFORM_INTERRUPT_MAX) {
        rte.mask = 1;
    }

    ioapic_write_rte(ioapic, gsi, rte);
    release_qinterrupt_lock(&lock, flags);
}

void ioapic_configure_legacy_irq(
    uint8_t irq,
    apic_interrupt_delivery_mode_t delivery,
    apic_interrupt_dest_mode_t dest,
    uint32_t dest_lapic,
    uint8_t vector,
    bool mask
) {
    uint32_t gsi               = irq;
    irq_trigger_mode_t trigger = IRQ_TRIGGER_EDGE;
    irq_polarity_t polarity    = IRQ_POLARITY_HIGH;

    if (overrides[irq].remapped) {
        gsi      = overrides[irq].gsi;
        trigger  = overrides[irq].trigger;
        polarity = overrides[irq].polarity;
    }

    ioapic_configure_irq(gsi, trigger, polarity, delivery, dest, dest_lapic, vector, mask);
}