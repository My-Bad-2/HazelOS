#ifndef KERNEL_DRIVERS_MADT_H
#define KERNEL_DRIVERS_MADT_H 1

#include <uacpi/tables.h>
#include <uacpi/uacpi.h>

#ifdef __cplusplus
extern "C" {
#endif

void acpi_parse_tables(void);

#ifdef __cplusplus
}
#endif

#endif