#ifndef KERNEL_CPU_LAPIC_H
#define KERNEL_CPU_LAPIC_H 1

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    DELIVERY_MODE_FIXED = 0,
    DELIVERY_MODE_LOWEST_PRIO,
    DELIVERY_MODE_SMI,
    DELIVERY_MODE_NMI,
    DELIVERY_MODE_INIT,
    DELIVERY_MODE_STARTUP,
    DELIVERY_MODE_EXT_INT,
} lapic_interrupt_delivery_mode_t;

void lapic_init(void);
uint32_t lapic_local_id(void);

void lapic_send_ipi(uint8_t vector, uint32_t dest_lapic_id, lapic_interrupt_delivery_mode_t mode);
void lapic_send_self_ipi(uint8_t vector, lapic_interrupt_delivery_mode_t mode);
void lapic_send_broadcast_ipi(uint8_t vector, lapic_interrupt_delivery_mode_t mode);
void lapic_send_broadcast_self_ipi(uint8_t vector, lapic_interrupt_delivery_mode_t mode);

void lapic_send_eoi(void);

#ifdef __cplusplus
}
#endif

#endif