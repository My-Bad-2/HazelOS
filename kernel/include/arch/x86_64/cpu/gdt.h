#ifndef KERNEL_CPU_GDT_H
#define KERNEL_CPU_GDT_H 1

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define GDT_ENTRY_COUNT 6

#define KERNEL_CODE (offsetof(gdt_table_t, entries) + (1 * sizeof(gdt_entry_t)))
#define KERNEL_DATA (offsetof(gdt_table_t, entries) + (2 * sizeof(gdt_entry_t)))
#define USER_CODE32 (offsetof(gdt_table_t, entries) + (3 * sizeof(gdt_entry_t)))
#define USER_DATA   (offsetof(gdt_table_t, entries) + (4 * sizeof(gdt_entry_t)))
#define USER_CODE   (offsetof(gdt_table_t, entries) + (5 * sizeof(gdt_entry_t)))
#define TSS_BASE    (offsetof(gdt_table_t, tss))

typedef struct [[gnu::packed]] {
    uint16_t limit_low;
    uint16_t base_low;
    uint8_t base_middle;
    uint8_t access;
    uint8_t granularity;
    uint8_t base_high;
} gdt_entry_t;

typedef struct [[gnu::packed]] {
    uint16_t limit_low;
    uint16_t base_low;
    uint8_t base_middle;
    uint8_t access;
    uint8_t granularity;
    uint8_t base_high;
    uint32_t base_upper;
    uint32_t reserved;
} tss_descriptor_t;

typedef struct [[gnu::aligned(16)]] {
    uint32_t reserved0;
    uint64_t rsp[3];
    uint64_t reserved1;
    uint64_t ist[7];
    uint64_t reserved2;
    uint16_t reserved3;
    uint16_t iomap_base;
} tss_t;

typedef struct [[gnu::aligned(16)]] {
    gdt_entry_t entries[GDT_ENTRY_COUNT];
    tss_descriptor_t tss;
} gdt_table_t;

void tss_init(tss_t* tss, uintptr_t rsp);
void gdt_init(gdt_table_t* entry, tss_t* tss);
void gdt_load(gdt_table_t* entry);

static inline void update_tss_rsp0(tss_t* tss, uintptr_t stack_top) {
    if (!tss) {
        return;
    }

    tss->rsp[0] = stack_top;
}

#ifdef __cplusplus
}
#endif

#endif