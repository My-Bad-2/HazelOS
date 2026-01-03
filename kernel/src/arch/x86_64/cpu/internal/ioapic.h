#define IOAPIC_IOREGSEL 0x00
#define IOAPIC_IOWIN    0x10

#define IOAPIC_REG_ID   0x00
#define IOAPIC_REG_VER  0x01
#define IOAPIC_EOIR_REG 0x40

// The minimum address space required past the base address
#define IOAPIC_WINDOW_SIZE 0x44

// The minimum version that supported the EOIR
#define IOAPIC_EOIR_MIN_VERSION 0x20

// IO APIC register offsets
#define IOAPIC_REG_RTE(idx) (0x10 + 2 * (idx))

// Macros for extracting data from REG_ID
#define IOAPIC_ID_ID(v) (((v) >> 24) & 0xf)

// Macros for extracting data from REG_VER
#define IOAPIC_VER_MAX_REDIR_ENTRY(v) (((v) >> 16) & 0xff)
#define IOAPIC_VER_VERSION(v)         ((v) & 0xff)

// Macros for writing REG_RTE entries
#define IOAPIC_RTE_DST(v)             (((uint64_t)(v)) << 56)
#define IOAPIC_RTE_EXTENDED_DST_ID(v) (((uint64_t)((v) & 0xf)) << 48)
#define IOAPIC_RTE_MASKED             (1ULL << 16)
#define IOAPIC_RTE_TRIGGER_MODE(tm)   (((uint64_t)(tm)) << 15)
#define IOAPIC_RTE_POLARITY(p)        (((uint64_t)(p)) << 13)
#define IOAPIC_RTE_DST_MODE(dm)       (((uint64_t)(dm)) << 11)
#define IOAPIC_RTE_DELIVERY_MODE(dm)  ((((uint64_t)(dm)) & 0x7) << 8)
#define IOAPIC_RTE_VECTOR(x)          (((uint64_t)(x)) & 0xff)
#define IOAPIC_RTE_MASK               IOAPIC_RTE_VECTOR(0xff)

#define IOAPIC_RTE_REMOTE_IRR      (1ULL << 14)
#define IOAPIC_RTE_DELIVERY_STATUS (1ULL << 12)
