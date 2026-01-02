#ifndef KERNEL_CPU_EXCEPTION_H
#define KERNEL_CPU_EXCEPTION_H 1

#include <stdint.h>

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
};

typedef struct {
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

typedef void (*isr_handler_t)(interrupt_trapframe_t* tf, void* ctx);

typedef enum {
    IRQ_TRIGGER_EDGE = 0,
    IRQ_TRIGGER_LEVEl,
} irq_trigger_mode_t;

typedef enum {
    IRQ_POLARITY_HIGH = 0,
    IRQ_POLARITY_LOW,
} irq_polarity_t;

void init_isr_registry(void);

int register_interrupt_handler(
    uint8_t vector,
    uint8_t irq_line,
    isr_handler_t handler,
    void* ctx,
    irq_trigger_mode_t trigger,
    irq_polarity_t polarity
);

void deregister_interrupt_handler(uint8_t vector);

#endif