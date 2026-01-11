#ifndef KERNEL_DRIVERS_ACPI_H
#define KERNEL_DRIVERS_ACPI_H 1

#ifdef __cplusplus
extern "C" {
#endif

void acpi_early_init(void);
void acpi_init(void);

#ifdef __cplusplus
}
#endif

#endif