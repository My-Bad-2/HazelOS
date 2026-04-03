#include "drivers/madt.h"

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

static inline bool is_entry_valid(struct acpi_entry_hdr* entry, void* end) {
    return ((void*)entry < end) && (entry->length >= sizeof(struct acpi_entry_hdr)) &&
           ((void*)((uint8_t*)entry + entry->length) <= end);
}

bool acpi_parse_tables(void) {
    uacpi_table view;
    if (uacpi_table_find_by_signature(ACPI_MADT_SIGNATURE, &view) != UACPI_STATUS_OK) return false;

    struct acpi_madt* madt = view.ptr;

    uint8_t* start = (uint8_t*)(madt->entries);
    uint8_t* end   = (uint8_t*)(madt) + madt->hdr.length;
    uint8_t* iter  = start;

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

    size_t total_size =
        (acpi_info.ioapic_count * sizeof(struct acpi_madt_ioapic)) +
        (acpi_info.iso_count * sizeof(struct acpi_madt_interrupt_source_override)) +
        (acpi_info.nmi_src_count * sizeof(struct acpi_madt_nmi_source)) +
        (acpi_info.x2apic_count * sizeof(struct acpi_madt_x2apic)) +
        (acpi_info.x2apic_nmi_count * sizeof(struct acpi_madt_x2apic_nmi)) +
        (acpi_info.platform_int_count * sizeof(struct acpi_madt_platform_interrupt_source)) +
        (acpi_info.lapic_nmi_count * sizeof(struct acpi_madt_lapic_nmi));

    if (total_size > 0) {
        uint8_t* block = kmalloc(total_size);
        if (!block) {
            uacpi_table_unref(&view);
            return false;
        }

        // Map pointers into the contiguous block
        acpi_info.ioapics = (void*)block;

        block += acpi_info.ioapic_count * sizeof(*acpi_info.ioapics);
        acpi_info.isos = (void*)block;

        block += acpi_info.iso_count * sizeof(*acpi_info.isos);
        acpi_info.nmis = (void*)block;

        block += acpi_info.nmi_src_count * sizeof(*acpi_info.nmis);
        acpi_info.x2apics = (void*)block;

        block += acpi_info.x2apic_count * sizeof(*acpi_info.x2apics);
        acpi_info.x2apic_nmis = (void*)block;

        block += acpi_info.x2apic_nmi_count * sizeof(*acpi_info.x2apic_nmis);
        acpi_info.platform_ints = (void*)block;

        block += acpi_info.platform_int_count * sizeof(*acpi_info.platform_ints);
        acpi_info.lapic_nmis = (void*)block;
    }

    size_t counts[7] = {0};
    iter             = start;

    while (is_entry_valid((struct acpi_entry_hdr*)iter, end)) {
        struct acpi_entry_hdr* entry = (struct acpi_entry_hdr*)iter;

        switch (entry->type) {
            case ACPI_MADT_ENTRY_TYPE_IOAPIC:
                memcpy(&acpi_info.ioapics[counts[0]++], entry, sizeof(struct acpi_madt_ioapic));
                break;
            case ACPI_MADT_ENTRY_TYPE_INTERRUPT_SOURCE_OVERRIDE:
                memcpy(
                    &acpi_info.isos[counts[1]++],
                    entry,
                    sizeof(struct acpi_madt_interrupt_source_override)
                );
                break;
            case ACPI_MADT_ENTRY_TYPE_NMI_SOURCE:
                memcpy(&acpi_info.nmis[counts[2]++], entry, sizeof(struct acpi_madt_nmi_source));
                break;
            case ACPI_MADT_ENTRY_TYPE_LOCAL_X2APIC:
                memcpy(&acpi_info.x2apics[counts[3]++], entry, sizeof(struct acpi_madt_x2apic));
                break;
            case ACPI_MADT_ENTRY_TYPE_LOCAL_X2APIC_NMI:
                memcpy(
                    &acpi_info.x2apic_nmis[counts[4]++],
                    entry,
                    sizeof(struct acpi_madt_x2apic_nmi)
                );
                break;
            case ACPI_MADT_ENTRY_TYPE_PLATFORM_INTERRUPT_SOURCES:
                memcpy(
                    &acpi_info.platform_ints[counts[5]++],
                    entry,
                    sizeof(struct acpi_madt_platform_interrupt_source)
                );
                break;
            case ACPI_MADT_ENTRY_TYPE_LAPIC_NMI:
                memcpy(
                    &acpi_info.lapic_nmis[counts[6]++],
                    entry,
                    sizeof(struct acpi_madt_lapic_nmi)
                );
                break;
            default:
                break;
        }

        iter += entry->length;
    }

    uacpi_table_unref(&view);
    return true;
}

size_t acpi_get_ioapic_count(void) {
    return acpi_info.ioapic_count;
}

size_t acpi_get_iso_count(void) {
    return acpi_info.iso_count;
}

struct acpi_madt_ioapic* acpi_get_ioapics(void) {
    return acpi_info.ioapics;
}

struct acpi_madt_interrupt_source_override* acpi_get_isos(void) {
    return acpi_info.isos;
}