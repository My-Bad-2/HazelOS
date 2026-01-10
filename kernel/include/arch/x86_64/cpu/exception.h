#ifndef KERNEL_CPU_EXCEPTION_H
#define KERNEL_CPU_EXCEPTION_H 1

#include <stdint.h>

#define GSI_NONE 0xffffffff

typedef struct [[gnu::aligned(16)]] {
    uint64_t r15, r14, r13, r12, r11, r10, r9, r8;
    uint64_t rbp, rdi, rsi, rdx, rcx, rbx, rax;

    uint64_t vector;
    uint64_t error_code;
    uint64_t rip;
    uint64_t cs;
    uint64_t rflags;
    uint64_t rsp;
    uint64_t ss;
} interrupt_trapframe_t;

enum {
    EXCEPTION_DIVIDE_BY_ZERO = 0,
    EXCEPTION_DEBUG,
    EXCEPTION_NON_MASKABLE_INTERRUPT,
    EXCEPTION_BREAKPOINT,
    EXCEPTION_OVERFLOW,
    EXCEPTION_BOUND_RANGE,
    EXCEPTION_INVALID_OPCODE,
    EXCEPTION_DEVICE_NOT_AVAILABLE,
    EXCEPTION_DOUBLE_FAULT,
    EXCEPTION_INVALID_TSS = 10,
    EXCEPTION_SEGMENT_NOT_PRESENT,
    EXCEPTION_STACK_SEGMENT_FAULT,
    EXCEPTION_GENERAL_PROTECTION_FAULT,
    EXCEPTION_PAGE_FAULT,
    EXCEPTION_X87_FLOATING_POINT = 16,
    EXCEPTION_ALIGNMENT_CHECK,
    EXCEPTION_MACHINE_CHECK,
    EXCEPTION_SIMD_FLOATING_POINT,
    EXCEPTION_VIRTUALIZATION,
    EXCEPTION_CONTROL_PROTECTION,
    EXCEPTION_HYPERVISOR_INJECTION = 28,
    EXCEPTION_VMM_COMMUNICATION,
    EXCEPTION_SECURITY,

    PLATFORM_INTERRUPT_BASE = 32,
    PLATFORM_INTERRUPT_MAX  = 255,

    IRQ_TIMER = 32,

    INTERRUPT_IPI_GENERIC = 248,
    INTERRUPT_IPI_RESCHEDULE,
    INTERRUPT_IPI_INTERRUPT,
    INTERRUPT_IPI_HALT,
    INTERRUPT_APIC_TIMER,
    INTERRUPT_APIC_ERROR,
    INTERRUPT_APIC_PMI,
    INTERRUPT_APIC_SPURIOUS,
};

typedef void (*isr_handler_t)(interrupt_trapframe_t* tf, void* ctx);

typedef enum {
    IRQ_TRIGGER_EDGE = 0,
    IRQ_TRIGGER_LEVEL,
} irq_trigger_mode_t;

typedef enum {
    IRQ_POLARITY_HIGH = 0,
    IRQ_POLARITY_LOW,
} irq_polarity_t;

typedef enum {
    DELIVERY_MODE_FIXED = 0,
    DELIVERY_MODE_LOWEST_PRIO,
    DELIVERY_MODE_SMI,
    DELIVERY_MODE_NMI,
    DELIVERY_MODE_INIT,
    DELIVERY_MODE_STARTUP,
    DELIVERY_MODE_EXT_INT,
} apic_interrupt_delivery_mode_t;

typedef enum {
    DESTMODE_PHYSICAL = 0,
    DESTMODE_LOGICAL  = 1,
} apic_interrupt_dest_mode_t;

void init_isr_registry(void);

int register_external_interrupt_handler(
    uint8_t vector,
    isr_handler_t handler,
    void* ctx,
    irq_trigger_mode_t trigger,
    irq_polarity_t polarity,
    apic_interrupt_delivery_mode_t delivery,
    apic_interrupt_dest_mode_t dest,
    uint32_t dest_apic,
    uint32_t gsi
);

int register_interrupt_handler(
    uint8_t vector,
    isr_handler_t handler,
    void* ctx,
    irq_trigger_mode_t trigger,
    irq_polarity_t polarity
);

int register_external_irq_handler(
    uint8_t vector,
    isr_handler_t handler,
    void* ctx,
    apic_interrupt_delivery_mode_t delivery,
    apic_interrupt_dest_mode_t dest,
    uint32_t dest_apic
);

void deregister_external_interrupt_handler(uint8_t vector);
void deregister_interrupt_handler(uint8_t vector);
void deregister_external_irq_handler(uint8_t vector);

#endif