#ifndef KERNEL_CPU_LAPIC_H
#define KERNEL_CPU_LAPIC_H 1

#include <stddef.h>
#include <stdint.h>

#include "cpu/exception.h"
#include "drivers/arch_timer.h"

#ifdef __cplusplus
extern "C" {
#endif

void lapic_init(void);
uint32_t lapic_local_id(void);

void lapic_send_ipi(uint8_t vector, uint32_t dest_lapic_id, apic_interrupt_delivery_mode_t mode);
void lapic_send_self_ipi(uint8_t vector, apic_interrupt_delivery_mode_t mode);
void lapic_send_broadcast_ipi(uint8_t vector, apic_interrupt_delivery_mode_t mode);
void lapic_send_broadcast_self_ipi(uint8_t vector, apic_interrupt_delivery_mode_t mode);

void lapic_send_init(uint32_t dest_lapic_id);
void lapic_send_startup(uint32_t dest_lapic_id, uint8_t vector);
void lapic_send_nmi(uint32_t dest_lapic_id);

void lapic_send_eoi(void);
void lapic_set_tpr(uint8_t priority);
uint8_t lapic_get_tpr(void);

void lapic_timer_calibrate(void);
void lapic_timer_mask(void);
void lapic_timer_unmask(void);
void lapic_timer_stop(void);
void lapic_timer_start(size_t ticks);
void lapic_configure_timer(timer_mode_t mode, uint8_t vector, uint64_t count);

#ifdef __cplusplus
}
#endif

#endif