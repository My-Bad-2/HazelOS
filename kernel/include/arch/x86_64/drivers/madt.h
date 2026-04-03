#ifndef KERNEL_DRIVERS_MADT_H
#define KERNEL_DRIVERS_MADT_H 1

#include <uacpi/acpi.h>
#include <uacpi/tables.h>
#include <uacpi/uacpi.h>

#ifdef __cplusplus
extern "C" {
#endif

bool acpi_parse_tables(void);

struct acpi_madt_ioapic* acpi_get_ioapics(void);
struct acpi_madt_interrupt_source_override* acpi_get_isos(void);

size_t acpi_get_ioapic_count(void);
size_t acpi_get_iso_count(void);

#ifdef __cplusplus
}
#endif

#endif