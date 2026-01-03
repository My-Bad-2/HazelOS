#ifndef KERNEL_CPU_IOAPIC_H
#define KERNEL_CPU_IOAPIC_H 1

#include <stdint.h>

#include "cpu/exception.h"

#ifdef __cplusplus
extern "C" {
#endif

void ioapic_init(void);
bool ioapic_is_valid_irq(uint32_t gsi);
bool ioapic_is_initialized(void);

void ioapic_configure_irq(
    uint32_t gsi,
    irq_trigger_mode_t trigger,
    irq_polarity_t polarity,
    apic_interrupt_delivery_mode_t delivery,
    apic_interrupt_dest_mode_t dest,
    uint32_t dest_apic,
    uint8_t vector,
    bool mask
);
void ioapic_mask_irq(uint32_t gsi, bool mask);
void ioapic_configure_irq_vector(uint32_t gsi, uint8_t vector);
void ioapic_configure_legacy_irq(
    uint8_t irq,
    apic_interrupt_delivery_mode_t delivery,
    apic_interrupt_dest_mode_t dest,
    uint32_t dest_lapic,
    uint8_t vector,
    bool mask
);

void ioapic_send_eoi(uint32_t gsi, uint8_t vector);
uint32_t ioapic_get_gsi(uint8_t irq);

#ifdef __cplusplus
}
#endif

#endif