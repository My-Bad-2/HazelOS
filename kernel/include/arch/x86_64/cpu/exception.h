#ifndef KERNEL_CPU_EXCEPTION_H
#define KERNEL_CPU_EXCEPTION_H 1

#include <stddef.h>
#include <stdint.h>

#define GSI_NONE 0xffffffff

#ifdef __cplusplus
extern "C" {
#endif

struct interrupt_trapframe {
    uint64_t r15, r14, r13, r12, r11, r10, r9, r8;
    uint64_t rbp, rdi, rsi, rdx, rcx, rbx, rax;

    uint64_t vector;
    uint64_t error_code;
    uint64_t rip;
    uint64_t cs;
    uint64_t rflags;
    uint64_t rsp;
    uint64_t ss;
};

typedef struct {
    uint64_t r15;
    uint64_t r14;
    uint64_t r13;
    uint64_t r12;
    uint64_t rbp;
    uint64_t rbx;
    uint64_t rip;  // Return address
} switch_context_t;

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

    DYNAMIC_VECTOR_BASE   = 48,
    DYNAMIC_VECTOR_MAX    = 245,
    INTERRUPT_IPI_GENERIC = 247,
    INTERRUPT_IPI_TLB,
    INTERRUPT_IPI_RESCHEDULE,
    INTERRUPT_IPI_INTERRUPT,
    INTERRUPT_IPI_HALT,
    INTERRUPT_APIC_TIMER,
    INTERRUPT_APIC_ERROR,
    INTERRUPT_APIC_PMI,
    INTERRUPT_APIC_SPURIOUS,
};

typedef enum {
    IRQ_TRIGGER_EDGE = 0,
    IRQ_TRIGGER_LEVEL,
} irq_trigger_mode_t;

typedef enum {
    IRQ_POLARITY_HIGH = 0,
    IRQ_POLARITY_LOW,
} irq_polarity_t;

typedef enum {
    DELIVERY_MODE_FIXED       = 0,
    DELIVERY_MODE_LOWEST_PRIO = 1,
    DELIVERY_MODE_SMI         = 2,
    DELIVERY_MODE_NMI         = 4,
    DELIVERY_MODE_INIT        = 5,
    DELIVERY_MODE_STARTUP     = 6,
    DELIVERY_MODE_EXT_INT     = 7,
} apic_interrupt_delivery_mode_t;

typedef enum {
    DESTMODE_PHYSICAL = 0,
    DESTMODE_LOGICAL  = 1,
} apic_interrupt_dest_mode_t;

typedef enum {
    IRQ_NONE = 0,     // This interrupt wasn't from my device
    IRQ_HANDLED,      // I handled it completely in the Hard IRQ context
    IRQ_WAKE_THREAD,  // It's mine, wake up my dedicated thread to process it
} irq_return_t;

typedef irq_return_t (*isr_primary_handler_t)(struct interrupt_trapframe* tf, void* ctx);
typedef void (*isr_threaded_handler_t)(void* ctx);

void init_isr_registry(void);

typedef struct {
    irq_trigger_mode_t trigger;
    irq_polarity_t polarity;
    apic_interrupt_delivery_mode_t delivery;
    apic_interrupt_dest_mode_t dest;
    uint32_t dest_apic;
    uint32_t gsi;
    bool is_external;
} irq_config_t;

int register_irq(
    uint8_t vector,
    isr_primary_handler_t handler,
    void* ctx,
    const irq_config_t* config
);
int register_threaded_irq(
    uint8_t vector,
    isr_primary_handler_t primary_handler,
    isr_threaded_handler_t threaded_handler,
    void* ctx,
    const irq_config_t* config,
    const char* thread_name
);

void free_irq(uint8_t vector, isr_primary_handler_t handler, void* ctx);

int irq_alloc_vector(void);
int irq_alloc_vectors(size_t count);

void irq_free_vector(uint8_t vector);
void irq_free_vectors(uint8_t base, size_t count);

#ifdef __cplusplus
}
#endif

#endif