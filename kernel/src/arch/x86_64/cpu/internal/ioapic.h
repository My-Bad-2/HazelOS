#include <stdint.h>

#define IOAPIC_IOREGSEL 0x00
#define IOAPIC_IOWIN    0x10

#define IOAPIC_REG_ID   0x00
#define IOAPIC_REG_VER  0x01
#define IOAPIC_EOIR_REG 0x40

#define IOAPIC_WINDOW_SIZE      0x44
#define IOAPIC_EOIR_MIN_VERSION 0x20

#define IOAPIC_REG_RTE(idx) (0x10 + 2 * (idx))

// Macros for extracting data from REG_VER
#define IOAPIC_VER_MAX_REDIR_ENTRY(v) (((v) >> 16) & 0xff)
#define IOAPIC_VER_VERSION(v)         ((v) & 0xff)

typedef union {
    struct {
        uint64_t vector          : 8;
        uint64_t delivery_mode   : 3;
        uint64_t dest_mode       : 1;
        uint64_t delivery_status : 1;
        uint64_t polarity        : 1;
        uint64_t remote_irr      : 1;
        uint64_t trigger_mode    : 1;
        uint64_t mask            : 1;
        uint64_t reserved        : 39;
        uint64_t destination     : 8;
    };
    uint64_t raw;
    struct {
        uint32_t low;
        uint32_t high;
    };
} ioapic_rte_t;