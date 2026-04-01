#include "cpu/gdt.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "libs/log.h"
#include "memory/memory.h"
#include "memory/pagemap.h"
#include "memory/vma.h"

#define GDT_ACCESS_TSS 0x09

#define GDT_ACCESS_ACCESSED   0x01
#define GDT_ACCESS_READWRITE  0x02
#define GDT_ACCESS_CONFORMING 0x04
#define GDT_ACCESS_EXECUTABLE 0x08
#define GDT_ACCESS_SEGMENT    0x10
#define GDT_ACCESS_RING0      0x00
#define GDT_ACCESS_RING3      0x60
#define GDT_ACCESS_PRESENT    0x80

#define GDT_FLAG_LONG_MODE 0x20
#define GDT_FLAG_PAGE_GRAN 0x80

static uint8_t* nmi_stack             = nullptr;
static uint8_t* double_fault_stack    = nullptr;
static uint8_t* machine_check_stack   = nullptr;
static uint8_t* debug_exception_stack = nullptr;

extern void flush_gdt(void* gdtr, uint16_t cs, uint16_t ss);
extern void flush_tss(uint16_t offset);

static inline void
set_gdt_entry(gdt_entry_t* entry, uint64_t base, uint64_t limit, uint8_t access, uint8_t flags) {
    ASSERT(entry);

    entry->base_low    = (base & 0xffff);
    entry->base_middle = (base >> 16) & 0xff;
    entry->base_high   = (base >> 24) & 0xff;

    entry->limit_low   = (limit & 0xffff);
    entry->granularity = ((limit >> 16) & 0x0f) | (flags & 0xf0);
    entry->access      = access;
}

static inline void set_tss_descriptor(tss_descriptor_t* desc, uintptr_t base, uint32_t limit) {
    ASSERT(desc);

    desc->base_low    = (base & 0xffff);
    desc->base_middle = (base >> 16) & 0xff;
    desc->base_high   = (base >> 24) & 0xff;
    desc->base_upper  = (base >> 32) & 0xffffffff;

    desc->limit_low   = (limit & 0xffff);
    desc->granularity = ((limit >> 16) & 0x0f);

    desc->access   = GDT_ACCESS_PRESENT | GDT_ACCESS_RING0 | GDT_ACCESS_TSS;
    desc->reserved = 0;
}

void gdt_init(gdt_table_t* gdt, tss_t* tss) {
    if (!gdt) return;

    KLOG_INIT_START("GDT");

    // 0: Null
    set_gdt_entry(&gdt->entries[0], 0, 0, 0, 0);

    // 1: Kernel Code
    set_gdt_entry(
        &gdt->entries[1],
        0,
        0xfffff,
        GDT_ACCESS_PRESENT | GDT_ACCESS_SEGMENT | GDT_ACCESS_EXECUTABLE | GDT_ACCESS_READWRITE,
        GDT_FLAG_PAGE_GRAN | GDT_FLAG_LONG_MODE
    );

    // 2: Kernel Data
    set_gdt_entry(
        &gdt->entries[2],
        0,
        0xfffff,
        GDT_ACCESS_PRESENT | GDT_ACCESS_SEGMENT | GDT_ACCESS_READWRITE,
        GDT_FLAG_PAGE_GRAN
    );

    // 3: User Code 32 (For SYSRET)
    set_gdt_entry(
        &gdt->entries[3],
        0,
        0xfffff,
        GDT_ACCESS_PRESENT | GDT_ACCESS_SEGMENT | GDT_ACCESS_READWRITE | GDT_ACCESS_EXECUTABLE |
            GDT_ACCESS_RING3,
        GDT_FLAG_PAGE_GRAN
    );

    // 4: User Data
    set_gdt_entry(
        &gdt->entries[4],
        0,
        0xfffff,
        GDT_ACCESS_PRESENT | GDT_ACCESS_SEGMENT | GDT_ACCESS_READWRITE | GDT_ACCESS_RING3,
        GDT_FLAG_PAGE_GRAN
    );

    // 5: User Code
    set_gdt_entry(
        &gdt->entries[5],
        0,
        0xfffff,
        GDT_ACCESS_PRESENT | GDT_ACCESS_SEGMENT | GDT_ACCESS_READWRITE | GDT_ACCESS_EXECUTABLE |
            GDT_ACCESS_RING3,
        GDT_FLAG_LONG_MODE | GDT_FLAG_PAGE_GRAN
    );

    uintptr_t tss_base = (uintptr_t)tss;
    uint32_t tss_limit = sizeof(tss_t) - 1;

    set_tss_descriptor(&gdt->tss, tss_base, tss_limit);

    KLOG_INIT_OK();
}

void tss_init(tss_t* tss, uintptr_t rsp) {
    ASSERT(tss);

    KLOG_INIT_START("TSS");
    memset(tss, 0, sizeof(tss_t));

    if (!nmi_stack && !double_fault_stack) {
        nmi_stack = vmalloc(
            kernel_space,
            nullptr,
            PAGE_SIZE_SMALL,
            VMM_FLAG_READ | VMM_FLAG_WRITE | VMM_FLAG_STACK,
            CACHE_WRITE_BACK,
            PAGE_SIZE_SMALL
        );

        double_fault_stack = vmalloc(
            kernel_space,
            nullptr,
            PAGE_SIZE_SMALL,
            VMM_FLAG_READ | VMM_FLAG_WRITE | VMM_FLAG_STACK,
            CACHE_WRITE_BACK,
            PAGE_SIZE_SMALL
        );

        machine_check_stack = vmalloc(
            kernel_space,
            nullptr,
            PAGE_SIZE_SMALL,
            VMM_FLAG_READ | VMM_FLAG_WRITE | VMM_FLAG_STACK,
            CACHE_WRITE_BACK,
            PAGE_SIZE_SMALL
        );

        debug_exception_stack = vmalloc(
            kernel_space,
            nullptr,
            PAGE_SIZE_SMALL,
            VMM_FLAG_READ | VMM_FLAG_WRITE | VMM_FLAG_STACK,
            CACHE_WRITE_BACK,
            PAGE_SIZE_SMALL
        );
    }

    if (!nmi_stack || !double_fault_stack || !machine_check_stack || !debug_exception_stack) {
        KLOG_INIT_FAIL();
        PANIC(
            "GDT: failed to allocate IST stacks nmi=%p df=%p mc=%p dbg=%p\n",
            nmi_stack,
            double_fault_stack,
            machine_check_stack,
            debug_exception_stack
        );
    }

    tss->rsp[0] = rsp;

    // if the kernel stack overflows, a double fault occurs.
    tss->ist[0] = (uintptr_t)double_fault_stack + PAGE_SIZE_SMALL;
    tss->ist[1] = (uintptr_t)nmi_stack + PAGE_SIZE_SMALL;
    tss->ist[2] = (uintptr_t)machine_check_stack + PAGE_SIZE_SMALL;
    tss->ist[3] = (uintptr_t)debug_exception_stack + PAGE_SIZE_SMALL;

    tss->iomap_base = sizeof(tss_t);
    KLOG_INIT_OK();
}

void gdt_load(gdt_table_t* entry) {
    struct [[gnu::packed]] {
        uint16_t limit;
        uint64_t base;
    } gdtr;

    gdtr.base  = (uintptr_t)entry;
    gdtr.limit = sizeof(gdt_table_t) - 1;

    uint16_t cs         = KERNEL_CODE;
    uint16_t ss         = KERNEL_DATA;
    uint16_t tss_offset = TSS_BASE;

    flush_gdt(&gdtr, cs, ss);
    flush_tss(tss_offset);
}