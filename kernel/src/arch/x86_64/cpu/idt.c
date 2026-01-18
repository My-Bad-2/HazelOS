#include "cpu/idt.h"

#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "cpu/exception.h"
#include "cpu/gdt.h"
#include "libs/log.h"
#include "memory/memory.h"
#include "memory/pagemap.h"
#include "memory/vma.h"

#define IDT_ATTR_PRESENT   0x80
#define IDT_ATTR_RING0     0x00
#define IDT_ATTR_RING3     0x60
#define IDT_TYPE_INTERRUPT 0x0e
#define IDT_TYPE_TRAP      0x0f

extern void* isr_stub_table[IDT_ENTRY_COUNT];

static idt_table_t* idt = nullptr;

static void set_idt_gate(int vector, void* handler, uint8_t ist, uint8_t type_attr) {
    ASSERT(idt);
    uint64_t handler_addr = (uint64_t)handler;

    idt_entry_t* entry = &idt->entries[vector];

    entry->offset_low    = handler_addr & 0xffff;
    entry->offset_middle = (handler_addr >> 16) & 0xffff;
    entry->offset_high   = (handler_addr >> 32) & 0xffffffff;

    entry->segment_selector = KERNEL_CODE;

    entry->ist        = ist;
    entry->attributes = type_attr;
    entry->reserved   = 0;
}

void idt_init(void) {
    if (idt != nullptr) {
        KLOG_DEBUG("IDT: already initialized\n");
        return;
    }

    idt = vmm_alloc(
        &kernel_space,
        sizeof(idt_table_t),
        VMM_FLAG_READ | VMM_FLAG_WRITE | VMM_FLAG_GLOBAL,
        CACHE_WRITE_BACK,
        PAGE_SIZE_SMALL
    );

    if (!idt) {
        errno = ENOMEM;
        PANIC(
            "IDT: failed to allocate IDT Table bytes=0x%zx errno=%d\n",
            sizeof(idt_table_t),
            errno
        );
        return;
    }

    memset(idt, 0, sizeof(idt_table_t));

    uint8_t ist   = 0;
    uint8_t flags = IDT_ATTR_PRESENT | IDT_ATTR_RING0 | IDT_TYPE_INTERRUPT;

    for (int i = 0; i < IDT_ENTRY_COUNT; ++i) {
        switch (i) {
            case EXCEPTION_DOUBLE_FAULT:
                ist = 1;
                break;
            case EXCEPTION_NON_MASKABLE_INTERRUPT:
                ist = 2;
                break;
            case EXCEPTION_MACHINE_CHECK:
                ist = 3;
                break;
            case EXCEPTION_DEBUG:
                ist = 4;
                break;
            default:
                ist = 0;
                break;
        }

        if (i == EXCEPTION_BREAKPOINT) {
            flags |= IDT_ATTR_RING3;
        } else {
            flags &= ~IDT_ATTR_RING3;
        }

        set_idt_gate(i, isr_stub_table[i], ist, flags);
    }

    KLOG_DEBUG("IDT: initialized entries=%d\n", IDT_ENTRY_COUNT);
}

void idt_load(void) {
    struct [[gnu::packed]] {
        uint16_t limit;
        uint64_t base;
    } idtr;

    idtr.limit = sizeof(idt_table_t) - 1;
    idtr.base  = (uint64_t)idt;

    asm volatile("lidt %0" ::"m"(idtr) : "memory");

    KLOG_DEBUG("IDT: loaded idtr[limit=0x%x base=0x%lx]\n", idtr.limit, idtr.base);
}