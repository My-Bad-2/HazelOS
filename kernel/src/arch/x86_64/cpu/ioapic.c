#include "cpu/ioapic.h"

#include <errno.h>
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
#include "memory/vma.h"
#include "memory/vmm.h"

#include "internal/ioapic.h"

#define NUM_IRQS 16

#define PORT_ADDRESS 0x22
#define PORT_DATA    0x23

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

static interrupt_lock_t lock;

// https://pdos.csail.mit.edu/6.828/2008/readings/ia32/MPspec.pdf Pg 3-8
static inline void imcr_connect_to_ioapic(void) {
    io_write8(PORT_ADDRESS, IMCR_PORT_ADDRESS);
    io_write8(PORT_DATA, IMCR_PASS_THROUGH_APIC);
}

static void map_ioapic_mmio(ioapic_t* ioapic, size_t index) {
    uintptr_t phys_base = align_down((uintptr_t)ioapic->desc.address, PAGE_SIZE_SMALL);

    ASSERT(((uintptr_t)ioapic->desc.address + IOAPIC_WINDOW_SIZE) <= (phys_base + PAGE_SIZE_SMALL));

    void* virt = nullptr;

    for (size_t i = 0; i < index; ++i) {
        uintptr_t other_phys = align_down(ioapics[i].desc.address, PAGE_SIZE_SMALL);
        if (other_phys == phys_base) {
            virt = (void*)align_down((uintptr_t)ioapics[i].virt_base, PAGE_SIZE_SMALL);
            break;
        }
    }

    if (!virt) {
        virt =
            vmm_alloc(&kernel_space, PAGE_SIZE_SMALL, VMM_FLAG_MMIO, CACHE_MMIO, PAGE_SIZE_SMALL);

        if (!virt) {
            errno = ENOMEM;
            PANIC("IOAPIC: failed to allocate MMIO page for ioapic=%zu errno=%d\n", index, errno);
        }

        pagemap_map_args_t args = {
            .virt_addr = virt,
            .phys_addr = (void*)phys_base,
            PAGE_SIZE_SMALL,
            VMM_FLAG_READ | VMM_FLAG_WRITE | VMM_FLAG_GLOBAL,
            CACHE_MMIO,
            PAGE_SIZE_SMALL
        };

        pagemap_t* map = vmm_get_kernel_pagemap();

        if (!pagemap_map(map, &args)) {
            errno = EIO;
            PANIC("IOAPIC: failed to map MMIO phys=0x%lx -> %p errno=%d\n", phys_base, virt, errno);
        }

        KLOG_DEBUG(
            "IOAPIC: mapped phys=0x%lx -> %p cache=%d flags=0x%x\n",
            phys_base,
            virt,
            CACHE_MMIO,
            VMM_FLAG_READ | VMM_FLAG_WRITE | VMM_FLAG_GLOBAL
        );
    }

    uintptr_t offset  = (uintptr_t)ioapic->desc.address - phys_base;
    ioapic->virt_base = (void*)((uintptr_t)virt + offset);
}

static inline uint32_t ioapic_read(ioapic_t* ioapic, uint8_t reg) {
    ASSERT(ioapic);

    uintptr_t cmd  = (uintptr_t)ioapic->virt_base + IOAPIC_IOREGSEL;
    uintptr_t data = (uintptr_t)ioapic->virt_base + IOAPIC_IOWIN;

    mmio_write32((void*)cmd, reg);
    return mmio_read32((void*)data);
}

static inline void ioapic_write(ioapic_t* ioapic, uint8_t reg, uint32_t val) {
    ASSERT(ioapic);

    uintptr_t cmd  = (uintptr_t)ioapic->virt_base + IOAPIC_IOREGSEL;
    uintptr_t data = (uintptr_t)ioapic->virt_base + IOAPIC_IOWIN;

    mmio_write32((void*)cmd, reg);
    mmio_write32((void*)data, val);
}

static uint64_t ioapic_read_redirection_entry(ioapic_t* ioapic, uint32_t gsi) {
    ASSERT(gsi >= ioapic->desc.gsi_base);
    uint32_t offset = gsi - ioapic->desc.gsi_base;
    ASSERT(offset <= ioapic->max_redirection_entry);

    uint8_t reg = (uint8_t)IOAPIC_REG_RTE(offset);

    uint64_t res = ioapic_read(ioapic, reg);
    res |= ((uint64_t)ioapic_read(ioapic, (uint8_t)(reg + 1)) << 32);

    return res;
}

static void ioapic_write_redirection_entry(ioapic_t* ioapic, uint32_t gsi, uint64_t val) {
    ASSERT(gsi >= ioapic->desc.gsi_base);
    uint32_t offset = gsi - ioapic->desc.gsi_base;
    ASSERT(offset <= ioapic->max_redirection_entry);

    uint8_t reg = (uint8_t)IOAPIC_REG_RTE(offset);
    ioapic_write(ioapic, reg, val & 0xffffffff);
    ioapic_write(ioapic, (uint8_t)(reg + 1), (val >> 32) & 0xffffffff);
}

static void init_ioapic_entries(ioapic_t* ioapic) {
    acquire_interrupt_lock(&lock);

    uint32_t ver                  = ioapic_read(ioapic, IOAPIC_REG_VER);
    ioapic->version               = IOAPIC_VER_VERSION(ver);
    ioapic->max_redirection_entry = IOAPIC_VER_MAX_REDIR_ENTRY(ver);

    for (uint32_t j = 0; j <= ioapic->max_redirection_entry; ++j) {
        uint32_t gsi = j + ioapic->desc.gsi_base;
        ioapic_write_redirection_entry(ioapic, gsi, IOAPIC_RTE_MASKED);
    }

    release_interrupt_lock(&lock);
}

static ioapic_t* find_ioapic_for_gsi(uint32_t gsi) {
    for (uint32_t i = 0; i < ioapic_count; ++i) {
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
        errno = ENOENT;
        PANIC("IOAPIC: could not resolve global IRQ gsi=%u errno=%d\n", gsi, errno);
    }

    return ioapic;
}

static void parse_iso_entry(
    struct acpi_madt_interrupt_source_override* iso,
    uint8_t* irq,
    uint32_t* gsi,
    irq_polarity_t* polarity,
    irq_trigger_mode_t* trigger
) {
    if (!iso) {
        return;
    }

    if (iso->bus != 0) {
        errno = EINVAL;
        PANIC("IOAPIC: invalid bus for interrupt override bus=%u errno=%d\n", iso->bus, errno);
    }

    if (irq) {
        *irq = iso->source;
    }

    if (gsi) {
        *gsi = iso->gsi;
    }

    // Flag is in format: 0xTPP (T=Trigger, P=Polarity)
    uint16_t flags = iso->flags;

    if (polarity) {
        uint8_t pol = flags & ACPI_MADT_POLARITY_MASK;

        switch (pol) {
            case ACPI_MADT_POLARITY_ACTIVE_HIGH:
                *polarity = IRQ_POLARITY_HIGH;
                break;
            case ACPI_MADT_POLARITY_ACTIVE_LOW:
                *polarity = IRQ_POLARITY_LOW;
                break;
            default:
                break;
        }
    }

    if (trigger) {
        uint8_t trig = flags & ACPI_MADT_TRIGGERING_MASK;

        switch (trig) {
            case ACPI_MADT_TRIGGERING_EDGE:
                *trigger = IRQ_TRIGGER_EDGE;
                break;
            case ACPI_MADT_TRIGGERING_LEVEL:
                *trigger = IRQ_TRIGGER_LEVEL;
                break;
            default:
                break;
        }
    }
}

static void resolve_legacy_irq(
    uint8_t irq,
    uint32_t* gsi,
    irq_trigger_mode_t* trigger,
    irq_polarity_t* polarity
) {
    ASSERT(gsi && trigger && polarity);

    *gsi      = irq;
    *trigger  = IRQ_TRIGGER_EDGE;
    *polarity = IRQ_POLARITY_HIGH;

    if (overrides[irq].remapped) {
        *gsi      = overrides[irq].gsi;
        *trigger  = overrides[irq].trigger;
        *polarity = overrides[irq].polarity;
    }
}

void ioapic_init(void) {
    if (ioapics) {
        return;
    }

    ioapic_count = acpi_get_ioapic_count();

    if (ioapic_count == 0) {
        KLOG_DEBUG("IOAPIC: no IOAPICs detected, skipping init\n");
        return;
    }

    KLOG_DEBUG("IOAPIC: init start count=%zu\n", ioapic_count);

    ioapics = kmalloc(sizeof(ioapic_t) * ioapic_count);

    if (!ioapics) {
        errno = ENOMEM;
        PANIC("IOAPIC: failed to allocate ioapic array count=%zu errno=%d\n", ioapic_count, errno);
    }

    struct acpi_madt_ioapic* descs                   = acpi_get_ioapics();
    struct acpi_madt_interrupt_source_override* isos = acpi_get_isos();
    size_t iso_count                                 = acpi_get_iso_count();

    imcr_connect_to_ioapic();

    for (size_t i = 0; i < ioapic_count; ++i) {
        ioapics[i].desc = descs[i];
        map_ioapic_mmio(&ioapics[i], i);
        init_ioapic_entries(&ioapics[i]);

        uintptr_t phys_base = align_down((uintptr_t)ioapics[i].desc.address, PAGE_SIZE_SMALL);

        KLOG_INFO(
            "IOAPIC: id=%u ver=0x%x max_redir=%u gsi_base=%u mapped=%p phys=0x%lx\n",
            ioapics[i].desc.id,
            ioapics[i].version,
            ioapics[i].max_redirection_entry,
            ioapics[i].desc.gsi_base,
            ioapics[i].virt_base,
            phys_base
        );
    }

    int isa = 0;
    for (int i = 0; i < NUM_IRQS; ++i) {
        if (isa >= iso_count) {
            break;
        }

        struct iso_override* override                   = &overrides[i];
        struct acpi_madt_interrupt_source_override* iso = &isos[isa];

        if (iso->source == i) {
            override->remapped = true;

            parse_iso_entry(
                &isos[isa],
                &override->irq,
                &override->gsi,
                &override->polarity,
                &override->trigger
            );

            KLOG_DEBUG(
                "IOAPIC: ISO irq=%u -> gsi=%u trig=%d pol=%d\n",
                override->irq,
                override->gsi,
                override->trigger,
                override->polarity
            );

            isa++;
        }
    }

    KLOG_INFO("IOAPIC: initialization complete count=%zu\n", ioapic_count);
}

bool ioapic_is_valid_irq(uint32_t gsi) {
    return find_ioapic_for_gsi(gsi) != nullptr;
}

void ioapic_send_eoi(uint32_t gsi, uint8_t vector) {
    ioapic_t* ioapic = require_ioapic(gsi);

    ASSERT(ioapic->version >= IOAPIC_EOIR_MIN_VERSION);

    acquire_interrupt_lock(&lock);

    uintptr_t cmd = (uintptr_t)ioapic->virt_base + IOAPIC_EOIR_REG;
    mmio_write32((void*)cmd, vector);

    release_interrupt_lock(&lock);
}

void ioapic_mask_irq(uint32_t gsi, bool mask) {
    ioapic_t* ioapic = require_ioapic(gsi);

    acquire_interrupt_lock(&lock);

    uint64_t val = ioapic_read_redirection_entry(ioapic, gsi);

    if (mask) {
        val |= IOAPIC_RTE_MASKED;
    } else {
        val &= ~IOAPIC_RTE_MASKED;
    }

    ioapic_write_redirection_entry(ioapic, gsi, val);

    release_interrupt_lock(&lock);

    KLOG_TRACE("IOAPIC: %smasked gsi=%u\n", mask ? "" : "un", gsi);
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

    acquire_interrupt_lock(&lock);

    if ((delivery == DELIVERY_MODE_FIXED) ||
        (delivery == DELIVERY_MODE_LOWEST_PRIO) &&
            ((vector < PLATFORM_INTERRUPT_BASE) || (vector > PLATFORM_INTERRUPT_MAX))) {
        mask = true;
    }

    uint64_t val = 0;
    val |= IOAPIC_RTE_TRIGGER_MODE(trigger);
    val |= IOAPIC_RTE_POLARITY(polarity);
    val |= IOAPIC_RTE_DELIVERY_MODE(delivery);
    val |= IOAPIC_RTE_DST_MODE(dest);
    val |= IOAPIC_RTE_DST(dest_apic);
    val |= IOAPIC_RTE_VECTOR(vector);

    if (mask) {
        val |= IOAPIC_RTE_MASKED;
    }

    ioapic_write_redirection_entry(ioapic, gsi, val);

    release_interrupt_lock(&lock);

    KLOG_TRACE(
        "IOAPIC: configured gsi=%u trig=%d pol=%d deliv=%d dest=%d lapic=0x%x vec=%u mask=%d\n",
        gsi,
        trigger,
        polarity,
        delivery,
        dest,
        dest_apic,
        vector,
        mask
    );
}

void ioapic_configure_irq_vector(uint32_t gsi, uint8_t vector) {
    ioapic_t* ioapic = require_ioapic(gsi);

    acquire_interrupt_lock(&lock);

    uint64_t val = ioapic_read_redirection_entry(ioapic, gsi);

    if ((vector < PLATFORM_INTERRUPT_BASE) || (vector > PLATFORM_INTERRUPT_MAX)) {
        val |= IOAPIC_RTE_MASKED;
    } else {
        val &= ~IOAPIC_RTE_MASKED;
    }

    val |= IOAPIC_RTE_VECTOR(vector);
    ioapic_write_redirection_entry(ioapic, gsi, val);

    release_interrupt_lock(&lock);

    KLOG_TRACE("IOAPIC: set vector gsi=%u vec=%u\n", gsi, vector);
}

void ioapic_configure_legacy_irq(
    uint8_t irq,
    apic_interrupt_delivery_mode_t delivery,
    apic_interrupt_dest_mode_t dest,
    uint32_t dest_lapic,
    uint8_t vector,
    bool mask
) {
    uint32_t gsi;
    irq_trigger_mode_t trigger;
    irq_polarity_t polarity;

    resolve_legacy_irq(irq, &gsi, &trigger, &polarity);
    ioapic_configure_irq(gsi, trigger, polarity, delivery, dest, dest_lapic, vector, mask);
}

uint32_t ioapic_get_gsi(uint8_t irq) {
    if (overrides[irq].remapped) {
        return overrides[irq].gsi;
    }

    return irq;
}

bool ioapic_is_initialized(void) {
    return ioapics != nullptr;
}