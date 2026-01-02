#ifndef KERNEL_CPU_IDT_H
#define KERNEL_CPU_IDT_H 1

#include <stdint.h>

#define IDT_ENTRY_COUNT 256

#ifdef __cplusplus
extern "C" {
#endif

typedef struct [[gnu::packed]] {
    uint16_t offset_low;
    uint16_t segment_selector;
    uint8_t ist;
    uint8_t attributes;
    uint16_t offset_middle;
    uint32_t offset_high;
    uint32_t reserved;
} idt_entry_t;

typedef struct [[gnu::aligned(0x10)]] {
    idt_entry_t entries[IDT_ENTRY_COUNT];
} idt_table_t;

void idt_init(void);
void idt_load(void);

#ifdef __cplusplus
}
#endif

#endif