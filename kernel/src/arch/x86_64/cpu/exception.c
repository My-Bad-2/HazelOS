#include "cpu/exception.h"

#include <errno.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>

#include "arch.h"
#include "cpu/idt.h"
#include "cpu/ioapic.h"
#include "cpu/lapic.h"
#include "cpu/pic.h"
#include "cpu/registers.h"
#include "cpu/smp.h"
#include "libs/log.h"
#include "libs/math.h"
#include "memory/memory.h"
#include "memory/pagemap.h"
#include "memory/paging.h"
#include "memory/vma.h"
#include "sched/scheduler.h"

typedef struct {
    isr_handler_t handler;
    void* ctx;

    irq_trigger_mode_t trigger;
    irq_polarity_t polarity;
} isr_entry_t;

static isr_entry_t* isr_registry = nullptr;

static const char* const exception_messages[32] = {
    "Divide by Zero",
    "Debug",
    "Non-Maskable Interrupt",
    "Breakpoint",
    "Overflow",
    "Bound Range Exceeded",
    "Invalid Opcode",
    "Device Not Available",
    "Double Fault",
    "Coprocessor Segment Overrun",
    "Invalid TSS",
    "Segment Not Present",
    "Stack-Segment Fault",
    "General Protection Fault",
    "Page Fault",
    "Reserved (15)",
    "x87 Floating-Point Exception",
    "Alignment Check",
    "Machine Check",
    "SIMD Floating-Point Exception",
    "Virtualization Exception",
    "Control Protection Exception",
    "Reserved (22)",
    "Reserved (23)",
    "Reserved (24)",
    "Reserved (25)",
    "Reserved (26)",
    "Reserved (27)",
    "Hypervisor Injection Exception",
    "VMM Communication Exception",
    "Security Exception",
    "Reserved (31)"
};

static void send_eoi(uint64_t vector) {
    if (ioapic_is_initialized() && vector >= PLATFORM_INTERRUPT_BASE) {
        lapic_send_eoi();
        return;
    }

    if ((vector >= PLATFORM_INTERRUPT_BASE) && (vector <= PLATFORM_INTERRUPT_BASE + 16)) {
        pic_send_eoi((uint8_t)vector);
    }
}

static void configure_irq(
    uint8_t vector,
    irq_trigger_mode_t trigger,
    irq_polarity_t polarity,
    apic_interrupt_delivery_mode_t delivery,
    apic_interrupt_dest_mode_t dest,
    uint32_t dest_apic,
    bool mask,
    uint32_t gsi
) {
    bool ioapic = ioapic_is_initialized();

    if (ioapic) {
        ioapic_configure_irq(gsi, trigger, polarity, delivery, dest, dest_apic, vector, mask);
        return;
    }

    if ((vector >= PLATFORM_INTERRUPT_BASE) && (vector <= PLATFORM_INTERRUPT_BASE + 16)) {
        pic_configure_irq(vector, mask, trigger);
    }
}

static void configure_legacy_irq(
    uint8_t vector,
    apic_interrupt_delivery_mode_t delivery,
    apic_interrupt_dest_mode_t dest,
    uint32_t dest_apic,
    bool mask
) {
    bool ioapic = ioapic_is_initialized();

    if (ioapic) {
        ioapic_configure_legacy_irq(
            vector - PLATFORM_INTERRUPT_BASE,
            delivery,
            dest,
            dest_apic,
            vector,
            mask
        );
        return;
    }

    if ((vector >= PLATFORM_INTERRUPT_BASE) && (vector <= PLATFORM_INTERRUPT_BASE + 16)) {
        pic_configure_irq(vector, mask, IRQ_TRIGGER_EDGE);
    }
}

void init_isr_registry(void) {
    if (isr_registry != nullptr) {
        errno = EAGAIN;
        KLOG_WARN("ISR: registry already initialized entries=%d\n", IDT_ENTRY_COUNT);
        return;
    }

    size_t size = sizeof(isr_entry_t) * IDT_ENTRY_COUNT;
    size        = align_up(size, PAGE_SIZE_SMALL);

    isr_registry = (isr_entry_t*)vmalloc(
        kernel_space,
        nullptr,
        size,
        VMM_FLAG_READ | VMM_FLAG_WRITE | VMM_FLAG_GLOBAL,
        CACHE_WRITE_BACK,
        PAGE_SIZE_SMALL
    );

    if (!isr_registry) {
        int err = errno ? errno : ENOMEM;
        errno   = err;
        PANIC("ISR: registry allocation failed bytes=0x%zx errno=%d\n", size, err);
    }

    KLOG_DEBUG("ISR: registry initialized entries=%d bytes=0x%zx\n", IDT_ENTRY_COUNT, size);
}

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
) {
    ASSERT(isr_registry);

    if (vector > (IDT_ENTRY_COUNT - 1)) {
        int err = errno = EINVAL;
        KLOG_WARN("ISR: invalid vector=%u errno=%d\n", vector, err);
        return -1;
    }

    if (isr_registry[vector].ctx) {
        // In a PCI shared interrupt system, append to a linked list here
        int err = errno = EBUSY;
        KLOG_WARN("ISR: vector=%u already registered errno=%d\n", vector, err);
        return -1;
    }

    isr_registry[vector].handler  = handler;
    isr_registry[vector].ctx      = ctx;
    isr_registry[vector].trigger  = trigger;
    isr_registry[vector].polarity = polarity;

    bool mask = false;

    KLOG_DEBUG(
        "ISR: registered vector=%u trigger=%d polarity=%d handler=%p ctx=%p\n",
        vector,
        trigger,
        polarity,
        handler,
        ctx
    );

    if (gsi != GSI_NONE) {
        configure_irq(vector, trigger, polarity, delivery, dest, dest_apic, mask, gsi);
    }

    return 0;
}

int register_external_irq_handler(
    uint8_t vector,
    isr_handler_t handler,
    void* ctx,
    apic_interrupt_delivery_mode_t delivery,
    apic_interrupt_dest_mode_t dest,
    uint32_t dest_apic
) {
    ASSERT(isr_registry);

    if (vector > (IDT_ENTRY_COUNT - 1)) {
        int err = errno = EINVAL;
        KLOG_WARN("ISR: invalid vector=%u errno=%d\n", vector, err);
        return -1;
    }

    if (isr_registry[vector].ctx) {
        // In a PCI shared interrupt system, append to a linked list here
        int err = errno = EBUSY;
        KLOG_WARN("ISR: vector=%u already registered errno=%d\n", vector, err);
        return -1;
    }

    isr_registry[vector].handler = handler;
    isr_registry[vector].ctx     = ctx;

    bool mask = false;

    configure_legacy_irq(vector, delivery, dest, dest_apic, mask);

    KLOG_DEBUG("ISR: registered vector=%u handler=%p ctx=%p\n", vector, handler, ctx);

    return 0;
}

int register_interrupt_handler(
    uint8_t vector,
    isr_handler_t handler,
    void* ctx,
    irq_trigger_mode_t trigger,
    irq_polarity_t polarity
) {
    ASSERT(isr_registry);

    if (vector > (IDT_ENTRY_COUNT - 1)) {
        int err = errno = EINVAL;
        KLOG_WARN("ISR: invalid vector=%u errno=%d\n", vector, err);
        return -1;
    }

    if (isr_registry[vector].ctx) {
        // In a PCI shared interrupt system, append to a linked list here
        int err = errno = EBUSY;
        KLOG_WARN("ISR: vector=%u already registered errno=%d\n", vector, err);
        return -1;
    }

    isr_registry[vector].handler  = handler;
    isr_registry[vector].ctx      = ctx;
    isr_registry[vector].trigger  = trigger;
    isr_registry[vector].polarity = polarity;

    KLOG_DEBUG(
        "ISR: registered vector=%u trigger=%d polarity=%d handler=%p ctx=%p\n",
        vector,
        trigger,
        polarity,
        handler,
        ctx
    );

    return 0;
}

void deregister_external_interrupt_handler(uint8_t vector) {
    if (vector > (IDT_ENTRY_COUNT - 1)) {
        int err = errno = EINVAL;
        KLOG_WARN("ISR: invalid vector=%u errno=%d\n", vector, err);
        return;
    }

    if (!isr_registry[vector].handler) {
        int err = errno = ENOENT;
        KLOG_WARN("ISR: no handler to deregister vector=%u errno=%d\n", vector, err);
        return;
    }

    isr_registry[vector].handler = nullptr;
    isr_registry[vector].ctx     = nullptr;

    irq_trigger_mode_t trigger = isr_registry[vector].trigger;
    irq_polarity_t polarity    = isr_registry[vector].polarity;

    bool mask = true;

    configure_irq(vector, trigger, polarity, DELIVERY_MODE_FIXED, DESTMODE_PHYSICAL, 0, mask, 0);
    KLOG_DEBUG("ISR: deregistered vector=%u\n", vector);
}

void deregister_interrupt_handler(uint8_t vector) {
    if (vector > (IDT_ENTRY_COUNT - 1)) {
        int err = errno = EINVAL;
        KLOG_WARN("ISR: invalid vector=%u errno=%d\n", vector, err);
        return;
    }

    if (!isr_registry[vector].handler) {
        int err = errno = ENOENT;
        KLOG_WARN("ISR: no handler to deregister vector=%u errno=%d\n", vector, err);
        return;
    }

    isr_registry[vector].handler = nullptr;
    isr_registry[vector].ctx     = nullptr;

    KLOG_DEBUG("ISR: deregistered vector=%u\n", vector);
}

void deregister_external_irq_handler(uint8_t vector) {
    if (vector > (IDT_ENTRY_COUNT - 1)) {
        int err = errno = EINVAL;
        KLOG_WARN("ISR: invalid vector=%u errno=%d\n", vector, err);
        return;
    }

    if (!isr_registry[vector].handler) {
        int err = errno = ENOENT;
        KLOG_WARN("ISR: no handler to deregister vector=%u errno=%d\n", vector, err);
        return;
    }

    isr_registry[vector].handler = nullptr;
    isr_registry[vector].ctx     = nullptr;

    bool mask = true;

    configure_legacy_irq(vector, DELIVERY_MODE_FIXED, DESTMODE_PHYSICAL, 0, mask);

    KLOG_DEBUG("ISR: deregistered vector=%u\n", vector);
}

static void buffer_append(char** buf, size_t* remaining, const char* fmt, ...) {
    ASSERT(buf && remaining);

    if (*remaining == 0) {
        return;
    }

    va_list args;
    va_start(args, fmt);

    int len = vsnprintf(*buf, *remaining, fmt, args);

    va_end(args);

    if (len < 0) {
        *remaining = 0;
        return;
    }

    if ((size_t)len >= *remaining) {
        *buf += *remaining;
        *remaining = 0;
    } else {
        *buf += len;
        *remaining -= (size_t)len;
    }
}

static void print_trap_frame(char* buf, size_t size, interrupt_trapframe_t* tf) {
    ASSERT(buf);

    char* curr       = buf;
    size_t remaining = size;
    uint64_t vector  = tf->vector;

    buffer_append(&curr, &remaining, "\n================ INTERRUPT/EXCEPTION =================\n");

    if (vector < 32) {
        buffer_append(&curr, &remaining, "VECTOR: %d (%s)\n", vector, exception_messages[vector]);
    } else {
        buffer_append(&curr, &remaining, "VECTOR: %d (External IRQ)\n", vector);
    }

    if (vector == EXCEPTION_DOUBLE_FAULT ||
        (vector >= EXCEPTION_INVALID_TSS && vector <= EXCEPTION_PAGE_FAULT) ||
        (vector == EXCEPTION_ALIGNMENT_CHECK) || (vector == EXCEPTION_SECURITY)) {
        buffer_append(&curr, &remaining, "ERROR CODE: 0x%lx ", tf->error_code);

        if (vector == EXCEPTION_PAGE_FAULT) {
            buffer_append(
                &curr,
                &remaining,
                "[%c%c%c%c%c%c]",
                (tf->error_code & X86_PAGE_FAULT_PRESENT) ? 'P' : '-',
                (tf->error_code & X86_PAGE_FAULT_WRITE) ? 'W' : '-',
                (tf->error_code & X86_PAGE_FAULT_USER) ? 'U' : 'K',
                (tf->error_code & X86_PAGE_FAULT_RSVD) ? 'R' : '-',
                (tf->error_code & X86_PAGE_FAULT_INSTRUCTION_FETCH) ? 'I' : '-',
                (tf->error_code & X86_PAGE_FAULT_PROTECTION_KEY) ? 'P' : '-'
            );

            buffer_append(&curr, &remaining, " FAULT ADDR (CR2) : 0x%016lx\n", read_cr2());
        } else {
            buffer_append(&curr, &remaining, "\n");
        }
    }

    buffer_append(&curr, &remaining, "------------------------------------------------------\n");

    buffer_append(
        &curr,
        &remaining,
        "RAX: 0x%016llx  RBX: 0x%016llx\n"
        "RCX: 0x%016llx  RDX: 0x%016llx\n"
        "RSI: 0x%016llx  RDI: 0x%016llx\n"
        "RBP: 0x%016llx  R8 : 0x%016llx\n"
        "R9 : 0x%016llx  R10: 0x%016llx\n"
        "R11: 0x%016llx  R12: 0x%016llx\n"
        "R13: 0x%016llx  R14: 0x%016llx\n"
        "R15: 0x%016llx\n",
        tf->rax,
        tf->rbx,
        tf->rcx,
        tf->rdx,
        tf->rsi,
        tf->rdi,
        tf->rbp,
        tf->r8,
        tf->r9,
        tf->r10,
        tf->r11,
        tf->r12,
        tf->r13,
        tf->r14,
        tf->r15
    );

    buffer_append(&curr, &remaining, "------------------------------------------------------\n");

    buffer_append(
        &curr,
        &remaining,
        "RIP   : 0x%016llx  CS: 0x%04x\n"
        "RSP   : 0x%016llx  SS: 0x%04x\n"
        "RFLAGS: 0x%016llx\n",
        tf->rip,
        tf->cs,
        tf->rsp,
        tf->ss,
        tf->rflags
    );

    if (vector < 32) {
        buffer_append(
            &curr,
            &remaining,
            "CR0   : 0x%016llx\nCR3   : 0x%016llx\nCR4   : 0x%016llx\n",
            read_cr0(),
            read_cr3(),
            read_cr4()
        );
    }

    buffer_append(&curr, &remaining, "======================================================\n");
}

static void handle_crash(interrupt_trapframe_t* tf) {
    char error_buffer[2048];

    print_trap_frame(error_buffer, sizeof(error_buffer), tf);
    arch_write(error_buffer);

    PANIC("Unhandled vector (%lu)", tf->vector);
}

// NOLINTNEXTLINE(misc-use-internal-linkage)
void x86_exception_handler(interrupt_trapframe_t* tf) {
    ASSERT(isr_registry);

    // Ignore APIC spurious interrupt
    if (tf->vector == INTERRUPT_APIC_SPURIOUS) {
        return;
    }

    per_cpu_data_t* cpu = smp_current_core();

    isr_handler_t handler = isr_registry[tf->vector].handler;
    void* ctx             = isr_registry[tf->vector].ctx;

    irq_trigger_mode_t trigger = isr_registry[tf->vector].trigger;

    if (trigger == IRQ_TRIGGER_EDGE) {
        send_eoi(tf->vector);
    }

    if (handler) {
        handler(tf, ctx);
    } else {
        handle_crash(tf);
    }

    if (trigger == IRQ_TRIGGER_LEVEL) {
        send_eoi(tf->vector);
    }

    scheduler_check_reschedule(tf);
}

// NOLINTNEXTLINE(misc-use-internal-linkage)
void x86_nmi_handler(interrupt_trapframe_t*) {
    PANIC("EXCEPTION: NMI called!");
}