#define INVALID_APIC_ID              0xffffffff
#define IA32_APIC_BASE_BSP           (1u << 8)
#define IA32_APIC_BASE_X2APIC_ENABLE (1u << 10)
#define IA32_APIC_BASE_XAPIC_ENABLE  (1u << 11)
#define NUM_ISA_IRQS                 16

// Memory-Mapped Registers (xAPIC offsets)
#define LAPIC_REG_ID                 0x020
#define LAPIC_REG_VERSION            0x030
#define LAPIC_REG_TASK_PRIORITY      0x080
#define LAPIC_REG_PROCESSOR_PRIORITY 0x0a0
#define LAPIC_REG_EOI                0x0b0
#define LAPIC_REG_LOGICAL_DST        0x0d0
#define LAPIC_REG_SPURIOUS_IRQ       0x0f0
#define LAPIC_REG_IN_SERVICE(x)      (0x100 + ((x) << 4))
#define LAPIC_REG_TRIGGER_MODE(x)    (0x180 + ((x) << 4))
#define LAPIC_REG_IRQ_REQUEST(x)     (0x200 + ((x) << 4))
#define LAPIC_REG_ERROR_STATUS       0x280
#define LAPIC_REG_LVT_CMCI           0x2f0
#define LAPIC_REG_IRQ_CMD_LOW        0x300
#define LAPIC_REG_IRQ_CMD_HIGH       0x310
#define LAPIC_REG_LVT_TIMER          0x320
#define LAPIC_REG_LVT_THERMAL        0x330
#define LAPIC_REG_LVT_PERF           0x340
#define LAPIC_REG_LVT_LINT0          0x350
#define LAPIC_REG_LVT_LINT1          0x360
#define LAPIC_REG_LVT_ERROR          0x370
#define LAPIC_REG_INIT_COUNT         0x380
#define LAPIC_REG_CURRENT_COUNT      0x390
#define LAPIC_REG_DIVIDE_CONF        0x3e0

// x2APIC MSRs
#define LAPIC_X2APIC_MSR_BASE     0x800
#define LAPIC_X2APIC_MSR_ICR      0x830
#define LAPIC_X2APIC_MSR_SELF_IPI 0x83f

// Spurious IRQ bitmasks
#define SVR_APIC_ENABLE        (1 << 8)
#define SVR_SPURIOUS_VECTOR(x) ((x) & 0xFF)

// Interrupt Command bitmasks (ICR)
#define ICR_VECTOR(x)        ((x) & 0xFF)
#define ICR_DELIVERY_MODE(x) (((uint32_t)(x)) << 8)
#define ICR_DST_MODE_LOGICAL (1 << 11)
#define ICR_DELIVERY_PENDING (1 << 12)
#define ICR_LEVEL_ASSERT     (1 << 14)
#define ICR_TRIGGER_LEVEL    (1 << 15)
#define ICR_DST_SHORTHAND(x) (((uint32_t)(x)) << 18)
#define ICR_DST(x)           (((uint32_t)(x)) << 24)

// Shorthands
#define ICR_DST_NONE           ICR_DST_SHORTHAND(0)
#define ICR_DST_SELF           ICR_DST_SHORTHAND(1)
#define ICR_DST_ALL            ICR_DST_SHORTHAND(2)
#define ICR_DST_ALL_MINUS_SELF ICR_DST_SHORTHAND(3)

// Common LVT bitmasks
#define LVT_VECTOR(x)        ((x) & 0xFF)
#define LVT_DELIVERY_MODE(x) (((uint32_t)(x)) << 8)
#define LVT_DELIVERY_PENDING (1 << 12)
#define LVT_MASKED           (1u << 16)

// LVT Timer bitmasks
#define LVT_TIMER_MODE_ONESHOT      (0u << 17)
#define LVT_TIMER_MODE_PERIODIC     (1u << 17)
#define LVT_TIMER_MODE_TSC_DEADLINE (2u << 17)

// Error Status Register (ESR) Bitmasks
#define LAPIC_ERR_SEND_CS_ERROR       (1 << 0)
#define LAPIC_ERR_RECV_CS_ERROR       (1 << 1)
#define LAPIC_ERR_SEND_ACCEPT_ERROR   (1 << 2)
#define LAPIC_ERR_RECV_ACCEPT_ERROR   (1 << 3)
#define LAPIC_ERR_REDIRECTABLE_IPI    (1 << 4)
#define LAPIC_ERR_SEND_ILLEGAL_VECTOR (1 << 5)
#define LAPIC_ERR_RECV_ILLEGAL_VECTOR (1 << 6)
#define LAPIC_ERR_ILLEGAL_REGISTER    (1 << 7)

#define TIMER_DIV_1  0xb
#define TIMER_DIV_16 0x3