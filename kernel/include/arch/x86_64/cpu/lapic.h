#ifndef KERNEL_CPU_LAPIC_H
#define KERNEL_CPU_LAPIC_H 1

#include <stddef.h>
#include <stdint.h>

#include "cpu/exception.h"

#ifdef __cplusplus
extern "C" {
#endif

void lapic_init(void);
uint32_t lapic_local_id(void);

void lapic_send_ipi(uint8_t vector, uint32_t dest_lapic_id, apic_interrupt_delivery_mode_t mode);
void lapic_send_self_ipi(uint8_t vector, apic_interrupt_delivery_mode_t mode);
void lapic_send_broadcast_ipi(uint8_t vector, apic_interrupt_delivery_mode_t mode);
void lapic_send_broadcast_self_ipi(uint8_t vector, apic_interrupt_delivery_mode_t mode);

void lapic_send_eoi(void);

#ifdef __cplusplus
}
#endif

#endif