#include "drivers/madt.h"

#include <errno.h>
#include <stdint.h>
#include <string.h>
#include <uacpi/acpi.h>
#include <uacpi/status.h>
#include <uacpi/tables.h>

#include "libs/log.h"
#include "memory/heap.h"

static struct {
    size_t ioapic_count;
    size_t iso_count;
    size_t nmi_src_count;
    size_t x2apic_count;
    size_t platform_int_count;
    size_t lapic_nmi_count;
    size_t x2apic_nmi_count;

    struct acpi_madt_ioapic* ioapics;
    struct acpi_madt_interrupt_source_override* isos;
    struct acpi_madt_nmi_source* nmis;
    struct acpi_madt_lapic_nmi* lapic_nmis;
    struct acpi_madt_x2apic* x2apics;
    struct acpi_madt_platform_interrupt_source* platform_ints;
    struct acpi_madt_x2apic_nmi* x2apic_nmis;
} acpi_info = {0};

static struct acpi_madt* madt_header = nullptr;

static inline bool is_entry_valid(struct acpi_entry_hdr* entry, void* end) {
    return ((void*)entry < end) && (entry->length >= sizeof(struct acpi_entry_hdr)) &&
           ((void*)((uint8_t*)entry + entry->length) <= end);
}

void acpi_parse_tables(void) {
    uacpi_table view;

    if (uacpi_table_find_by_signature(ACPI_MADT_SIGNATURE, &view) != UACPI_STATUS_OK) {
        errno = ENODEV;
        KLOG_WARN(
            "ACPI: MADT not found. APIC-based interrupt setup will be limited. errno=%d\n",
            errno
        );
        return;
    }

    struct acpi_madt* madt = view.ptr;
    size_t len             = madt->hdr.length;

    madt_header = kmalloc(len);

    if (!madt_header) {
        errno = ENOMEM;
        KLOG_ERROR("ACPI: failed to allocate MADT Header len=%u errno=%d\n", len, errno);
        uacpi_table_unref(&view);
        return;
    }

    memcpy(madt_header, madt, len);
    uacpi_table_unref(&view);

    KLOG_DEBUG(
        "ACPI: MADT header lapic_phys=0x%lx flags=0x%x length=%zu\n",
        (unsigned long)madt_header->local_interrupt_controller_address,
        madt_header->flags,
        len
    );

    uint8_t* start = (uint8_t*)(madt_header->entries);
    uint8_t* end   = (uint8_t*)(madt_header) + len;

    uint8_t* iter = start;
    while (is_entry_valid((struct acpi_entry_hdr*)iter, end)) {
        struct acpi_entry_hdr* entry = (struct acpi_entry_hdr*)iter;

        switch (entry->type) {
            case ACPI_MADT_ENTRY_TYPE_IOAPIC:
                acpi_info.ioapic_count++;
                break;
            case ACPI_MADT_ENTRY_TYPE_INTERRUPT_SOURCE_OVERRIDE:
                acpi_info.iso_count++;
                break;
            case ACPI_MADT_ENTRY_TYPE_NMI_SOURCE:
                acpi_info.nmi_src_count++;
                break;
            case ACPI_MADT_ENTRY_TYPE_LOCAL_X2APIC:
                acpi_info.x2apic_count++;
                break;
            case ACPI_MADT_ENTRY_TYPE_LOCAL_X2APIC_NMI:
                acpi_info.x2apic_nmi_count++;
                break;
            case ACPI_MADT_ENTRY_TYPE_PLATFORM_INTERRUPT_SOURCES:
                acpi_info.platform_int_count++;
                break;
            case ACPI_MADT_ENTRY_TYPE_LAPIC_NMI:
                acpi_info.lapic_nmi_count++;
                break;
            default:
                break;
        }

        iter += entry->length;
    }

    size_t length = 0;

    if (acpi_info.x2apic_count) {
        length            = sizeof(struct acpi_madt_x2apic) * acpi_info.x2apic_count;
        acpi_info.x2apics = kmalloc(length);

        if (!acpi_info.x2apics) {
            errno = ENOMEM;
            KLOG_ERROR(
                "ACPI: failed to allocate x2APIC entries count=%zu errno=%d\n",
                acpi_info.x2apic_count,
                errno
            );
            return;
        }
    }

    if (acpi_info.ioapic_count) {
        length            = sizeof(struct acpi_madt_ioapic) * acpi_info.ioapic_count;
        acpi_info.ioapics = kmalloc(length);

        if (!acpi_info.ioapics) {
            errno = ENOMEM;
            KLOG_ERROR(
                "ACPI: failed to allocate IOAPIC entries count=%zu errno=%d\n",
                acpi_info.ioapic_count,
                errno
            );
            return;
        }
    }

    if (acpi_info.iso_count) {
        length         = sizeof(struct acpi_madt_interrupt_source_override) * acpi_info.iso_count;
        acpi_info.isos = kmalloc(length);

        if (!acpi_info.isos) {
            errno = ENOMEM;
            KLOG_ERROR(
                "ACPI: failed to allocate ISO entries count=%zu errno=%d\n",
                acpi_info.iso_count,
                errno
            );
            return;
        }
    }

    if (acpi_info.nmi_src_count) {
        length         = sizeof(struct acpi_madt_nmi_source) * acpi_info.nmi_src_count;
        acpi_info.nmis = kmalloc(length);

        if (!acpi_info.nmis) {
            errno = ENOMEM;
            KLOG_ERROR(
                "ACPI: failed to allocate NMI source entries count=%zu errno=%d\n",
                acpi_info.nmi_src_count,
                errno
            );
            return;
        }
    }

    if (acpi_info.x2apic_nmi_count) {
        length                = sizeof(struct acpi_madt_x2apic_nmi) * acpi_info.x2apic_nmi_count;
        acpi_info.x2apic_nmis = kmalloc(length);

        if (!acpi_info.x2apic_nmis) {
            errno = ENOMEM;
            KLOG_ERROR(
                "ACPI: failed to allocate x2APIC NMI entries count=%zu errno=%d\n",
                acpi_info.x2apic_nmi_count,
                errno
            );
            return;
        }
    }

    if (acpi_info.platform_int_count) {
        length = sizeof(struct acpi_madt_platform_interrupt_source) * acpi_info.platform_int_count;
        acpi_info.platform_ints = kmalloc(length);

        if (!acpi_info.platform_ints) {
            errno = ENOMEM;
            KLOG_ERROR(
                "ACPI: failed to allocate platform interrupt entries count=%zu errno=%d\n",
                acpi_info.platform_int_count,
                errno
            );
            return;
        }
    }

    if (acpi_info.lapic_nmi_count) {
        length               = sizeof(struct acpi_madt_lapic_nmi) * acpi_info.lapic_nmi_count;
        acpi_info.lapic_nmis = kmalloc(length);

        if (!acpi_info.lapic_nmis) {
            errno = ENOMEM;
            KLOG_ERROR(
                "ACPI: failed to allocate LAPIC NMI entries count=%zu errno=%d\n",
                acpi_info.lapic_nmi_count,
                errno
            );
            return;
        }
    }

    int ioapic       = 0;
    int iso          = 0;
    int nmi_src      = 0;
    int x2apic       = 0;
    int platform_int = 0;
    int lapic_nmi    = 0;
    int x2apic_nmi   = 0;

    iter = start;
    while (is_entry_valid((struct acpi_entry_hdr*)iter, end)) {
        struct acpi_entry_hdr* entry = (struct acpi_entry_hdr*)iter;

        switch (entry->type) {
            case ACPI_MADT_ENTRY_TYPE_IOAPIC:
                if (ioapic < acpi_info.ioapic_count) {
                    memcpy(&acpi_info.ioapics[ioapic++], entry, sizeof(struct acpi_madt_ioapic));
                }
                break;
            case ACPI_MADT_ENTRY_TYPE_INTERRUPT_SOURCE_OVERRIDE:
                if (iso < acpi_info.iso_count) {
                    memcpy(
                        &acpi_info.isos[iso++],
                        entry,
                        sizeof(struct acpi_madt_interrupt_source_override)
                    );
                }
                break;
            case ACPI_MADT_ENTRY_TYPE_NMI_SOURCE:
                if (nmi_src < acpi_info.nmi_src_count) {
                    memcpy(&acpi_info.nmis[nmi_src++], entry, sizeof(struct acpi_madt_nmi_source));
                }
                break;
            case ACPI_MADT_ENTRY_TYPE_LOCAL_X2APIC:
                if (x2apic < acpi_info.x2apic_count) {
                    memcpy(&acpi_info.x2apics[x2apic++], entry, sizeof(struct acpi_madt_x2apic));
                }
                break;
            case ACPI_MADT_ENTRY_TYPE_LOCAL_X2APIC_NMI:
                if (x2apic_nmi < acpi_info.x2apic_nmi_count) {
                    memcpy(
                        &acpi_info.x2apic_nmis[x2apic_nmi++],
                        entry,
                        sizeof(struct acpi_madt_x2apic_nmi)
                    );
                }
                break;
            case ACPI_MADT_ENTRY_TYPE_PLATFORM_INTERRUPT_SOURCES:
                if (platform_int < acpi_info.platform_int_count) {
                    memcpy(
                        &acpi_info.platform_ints[platform_int++],
                        entry,
                        sizeof(struct acpi_madt_platform_interrupt_source)
                    );
                }
                break;
            case ACPI_MADT_ENTRY_TYPE_LAPIC_NMI:
                if (lapic_nmi < acpi_info.lapic_nmi_count) {
                    memcpy(
                        &acpi_info.lapic_nmis[lapic_nmi++],
                        entry,
                        sizeof(struct acpi_madt_lapic_nmi)
                    );
                }
                break;
            default:
                break;
        }

        iter += entry->length;
    }

    KLOG_DEBUG(
        "ACPI: MADT parsed ioapic=%zu iso=%zu nmi_src=%zu x2apic=%zu x2apic_nmi=%zu "
        "platform_int=%zu lapic_nmi=%zu\n",
        acpi_info.ioapic_count,
        acpi_info.iso_count,
        acpi_info.nmi_src_count,
        acpi_info.x2apic_count,
        acpi_info.x2apic_nmi_count,
        acpi_info.platform_int_count,
        acpi_info.lapic_nmi_count
    );
}