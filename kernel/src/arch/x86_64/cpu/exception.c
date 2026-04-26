#include "cpu/exception.h"

#include <stdarg.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "arch.h"
#include "cpu/idt.h"
#include "cpu/ioapic.h"
#include "cpu/lapic.h"
#include "cpu/pic.h"
#include "cpu/registers.h"
#include "cpu/smp.h"
#include "libs/log.h"
#include "libs/math.h"
#include "libs/slist.h"
#include "libs/spinlock.h"
#include "memory/heap.h"
#include "memory/memory.h"
#include "memory/paging.h"
#include "memory/vma.h"
#include "sched/process.h"
#include "sched/scheduler.h"
#include "sched/semaphore.h"

#define STORM_WINDOW_SIZE 100000
// Forgive shared IRQs just in case hardware state wasn't synced when the CPU read it
#define STORM_UNHANDLED_LIMIT 99000

struct isr_action {
    isr_primary_handler_t primary_handler;
    isr_threaded_handler_t threaded_handler;
    void* ctx;

    thread_t* thread;
    struct semaphore* wakeup_semaphore;
    atomic_bool thread_pending;

    struct slist_node node;
};

struct isr_entry {
    struct slist_head actions;
    irq_config_t config;
    rwlock_t lock;

    uint32_t irq_count;
    uint32_t unhandled_count;
    bool is_masked_by_storm;
};

static struct isr_entry* isr_registry = nullptr;
static uint64_t vector_bitmap[4]      = {0};
static qspinlock_t allocator_lock;

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

static void init_vector_allocator(void) {
    for (int i = 0; i < 4; ++i) {
        vector_bitmap[i] = UINT64_MAX;
    }

    for (size_t i = DYNAMIC_VECTOR_BASE; i <= DYNAMIC_VECTOR_MAX; ++i) {
        __clear_bit(i, vector_bitmap);
    }
}

static void irq_thread_runner(void* arg) {
    struct isr_action* action = (struct isr_action*)arg;

    while (true) {
        sema_down(action->wakeup_semaphore);

        atomic_store_explicit(&action->thread_pending, false, memory_order_release);

        if (action->threaded_handler) {
            action->threaded_handler(action->ctx);
        }
    }
}

void init_isr_registry(void) {
    if (isr_registry != nullptr) {
        KLOG_WARN("ISR: registry already initialized entries=%d\n", IDT_ENTRY_COUNT);
        return;
    }

    KLOG_INIT_START("ISR Registry");

    size_t size = align_up(sizeof(struct isr_entry) * IDT_ENTRY_COUNT, PAGE_SIZE_SMALL);

    isr_registry = kmalloc(size);
    if (!isr_registry) {
        KLOG_INIT_FAIL();
        PANIC("ISR: registry allocation failed bytes=0x%zx\n", size);
    }

    memset(isr_registry, 0, size);
    for (int i = 0; i < IDT_ENTRY_COUNT; ++i) {
        slist_init(&isr_registry[i].actions);
    }

    init_vector_allocator();

    KLOG_INIT_OK();
}

int register_irq(
    uint8_t vector,
    isr_primary_handler_t handler,
    void* ctx,
    const irq_config_t* config
) {
    ASSERT(isr_registry);

    if ((uint32_t)vector >= IDT_ENTRY_COUNT || !handler) {
        return -1;
    }

    struct isr_action* action = kmalloc(sizeof(struct isr_action));
    if (!action) {
        return -1;
    }

    action->primary_handler = handler;
    action->ctx             = ctx;

    bool is_first_handler = slist_empty(&isr_registry[vector].actions);
    slist_push(&action->node, &isr_registry[vector].actions);

    if (is_first_handler && config) {
        isr_registry[vector].config = *config;

        if (config->is_external) {
            configure_irq(
                vector,
                config->trigger,
                config->polarity,
                config->delivery,
                config->dest,
                config->dest_apic,
                false,
                config->gsi
            );
        }
    }

    return 0;
}

int register_threaded_irq(
    uint8_t vector,
    isr_primary_handler_t primary_handler,
    isr_threaded_handler_t threaded_handler,
    void* ctx,
    const irq_config_t* config,
    const char* thread_name
) {
    if ((size_t)vector >= IDT_ENTRY_COUNT || !primary_handler) {
        return -1;
    }

    struct isr_action* action = kmalloc(sizeof(struct isr_action));
    if (!action) {
        return -1;
    }

    action->primary_handler  = primary_handler;
    action->threaded_handler = threaded_handler;
    action->ctx              = ctx;
    atomic_init(&action->thread_pending, false);

    action->wakeup_semaphore = sema_create(0);

    action->thread = thread_create(
        thread_name,
        get_kernel_process(),
        kernel_space,
        SCHED_FIFO,
        (uintptr_t)irq_thread_runner,
        (uintptr_t)action,
        0,
        nullptr
    );
    scheduler_add_thread(action->thread);

    size_t flags = acquire_interrupt_lock(nullptr);
    acquire_write(&isr_registry[vector].lock);

    bool is_first = slist_empty(&isr_registry[vector].actions);
    slist_push(&action->node, &isr_registry[vector].actions);

    if (is_first && config) {
        isr_registry[vector].config = *config;

        if (config->is_external) {
            configure_irq(
                vector,
                config->trigger,
                config->polarity,
                config->delivery,
                config->dest,
                config->dest_apic,
                false,
                config->gsi
            );
        }
    }

    release_write(&isr_registry[vector].lock);
    release_interrupt_lock(nullptr, flags);
    return 0;
}

void free_irq(uint8_t vector, isr_primary_handler_t handler, void* ctx) {
    if ((uint32_t)vector >= IDT_ENTRY_COUNT || !isr_registry) {
        return;
    }

    size_t flags = acquire_interrupt_lock(nullptr);
    acquire_write(&isr_registry[vector].lock);

    struct slist_head* head = &isr_registry[vector].actions;
    struct slist_node* prev = nullptr;
    struct slist_node* curr = head->first;

    while (curr) {
        struct isr_action* entry = slist_entry(curr, struct isr_action, node);

        if (entry->primary_handler == handler && entry->ctx == ctx) {
            if (prev) {
                slist_del_after(prev);
            } else {
                slist_pop(head);
            }

            kfree(entry);

            if (slist_empty(head)) {
                irq_config_t* cfg = &isr_registry[vector].config;

                if (cfg->is_external) {
                    configure_irq(
                        vector,
                        cfg->trigger,
                        cfg->polarity,
                        DELIVERY_MODE_FIXED,
                        DESTMODE_PHYSICAL,
                        0,
                        true,
                        0
                    );
                }
            }

            break;
        }

        prev = curr;
        curr = curr->next;
    }

    release_write(&isr_registry[vector].lock);
    release_interrupt_lock(nullptr, flags);
}

int irq_alloc_vector(void) {
    size_t flags         = acquire_qinterrupt_lock(&allocator_lock);
    int allocated_vector = -1;

    for (int i = DYNAMIC_VECTOR_BASE; i <= DYNAMIC_VECTOR_MAX; ++i) {
        if (!__test_bit((size_t)i, vector_bitmap)) {
            __set_bit((size_t)i, vector_bitmap);
            allocated_vector = i;
            break;
        }
    }

    release_qinterrupt_lock(&allocator_lock, flags);

    if (allocated_vector == -1) {
        KLOG_WARN("IRQ: Vector allocation failed (exhauted)\n");
    }

    return allocated_vector;
}

int irq_alloc_vectors(size_t count) {
    if (count == 0 || count > 32 || (count & (count - 1)) != 0) {
        return -1;
    }

    size_t flags             = acquire_qinterrupt_lock(&allocator_lock);
    int base_vector          = -1;
    size_t found_consecutive = 0;

    for (int i = DYNAMIC_VECTOR_BASE; i <= DYNAMIC_VECTOR_MAX; ++i) {
        if (found_consecutive == 0 && ((size_t)i % count) != 0) {
            continue;
        }

        if (!__test_bit((size_t)i, vector_bitmap)) {
            if (found_consecutive == 0) {
                base_vector = i;
            }

            found_consecutive++;

            if (found_consecutive == count) {
                for (size_t j = 0; j < count; ++j) {
                    __set_bit((size_t)base_vector + j, vector_bitmap);
                }

                break;
            }
        } else {
            found_consecutive = 0;
            base_vector       = -1;
        }
    }

    release_qinterrupt_lock(&allocator_lock, flags);

    if (found_consecutive < count) {
        KLOG_WARN("IRQ: Contiguous vector allocation failed (Requested: %zu)\n", count);
        return -1;
    }

    return base_vector;
}

void irq_free_vector(uint8_t vector) {
    if (vector < DYNAMIC_VECTOR_BASE || vector > DYNAMIC_VECTOR_MAX) {
        return;
    }

    size_t flags = acquire_qinterrupt_lock(&allocator_lock);
    __clear_bit(vector, vector_bitmap);
    release_qinterrupt_lock(&allocator_lock, flags);
}

void irq_free_vectors(uint8_t base, size_t count) {
    if (base < DYNAMIC_VECTOR_BASE || (base + count - 1) > DYNAMIC_VECTOR_MAX) {
        return;
    }

    size_t flags = acquire_qinterrupt_lock(&allocator_lock);
    for (size_t i = 0; i < count; ++i) {
        __clear_bit((size_t)base + i, vector_bitmap);
    }

    release_qinterrupt_lock(&allocator_lock, flags);
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

static void print_trap_frame(char* buf, size_t size, struct interrupt_trapframe* tf) {
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

static void handle_crash(struct interrupt_trapframe* tf) {
    char error_buffer[2048];

    print_trap_frame(error_buffer, sizeof(error_buffer), tf);
    arch_write(LOG_ERROR, error_buffer);

    PANIC("Unhandled vector (%lu)", tf->vector);
}

static void check_interrupt_storm(uint8_t vector, bool handled) {
    struct isr_entry* entry = &isr_registry[vector];

    if (vector < PLATFORM_INTERRUPT_BASE || entry->is_masked_by_storm) {
        return;
    }

    entry->irq_count++;

    if (!handled) {
        entry->unhandled_count++;
    }

    if (entry->irq_count >= STORM_WINDOW_SIZE) {
        if (entry->unhandled_count >= STORM_UNHANDLED_LIMIT) {
            KLOG_ERROR(
                "IRQ: Interrupt storm detected on vector %zu (%zu unhandled out of %zu), Masking "
                "line to save system.\n",
                vector,
                entry->unhandled_count,
                entry->irq_count
            );

            entry->is_masked_by_storm = true;

            if (entry->config.is_external) {
                configure_irq(
                    vector,
                    entry->config.trigger,
                    entry->config.polarity,
                    DELIVERY_MODE_FIXED,
                    DESTMODE_PHYSICAL,
                    0,
                    true,
                    0
                );
            }
        }

        entry->irq_count       = 0;
        entry->unhandled_count = 0;
    }
}

// NOLINTNEXTLINE(misc-use-internal-linkage)
void x86_exception_handler(struct interrupt_trapframe* tf) {
    ASSERT(isr_registry);

    if (tf->vector >= IDT_ENTRY_COUNT) {
        handle_crash(tf);
        return;
    }

    if (tf->vector == INTERRUPT_APIC_SPURIOUS) {
        return;
    }

    per_cpu_data_t* cpu        = smp_current_core();
    irq_trigger_mode_t trigger = isr_registry[tf->vector].config.trigger;

    if (trigger == IRQ_TRIGGER_EDGE) {
        send_eoi(tf->vector);
    }

    bool handled = false;
    size_t flags = acquire_interrupt_lock(nullptr);
    acquire_read(&isr_registry[tf->vector].lock);

    struct slist_head* head = &isr_registry[tf->vector].actions;

    if (!slist_empty(head)) {
        struct isr_action* action;

        slist_for_each_entry(action, head, node) {
            if (!action) {
                break;
            }

            irq_return_t ret = action->primary_handler(tf, action->ctx);

            if (ret == IRQ_HANDLED) {
                handled = true;
            } else if (ret == IRQ_WAKE_THREAD) {
                handled = true;

                bool expected = false;
                if (atomic_compare_exchange_strong(&action->thread_pending, &expected, true)) {
                    sema_up(action->wakeup_semaphore);
                }
            }
        }
    } else if (tf->vector == EXCEPTION_PAGE_FAULT) {
        pf_handler(tf);
        handled = true;
    }

    check_interrupt_storm(tf->vector, handled);

    release_read(&isr_registry[tf->vector].lock);
    release_interrupt_lock(nullptr, flags);

    if (!handled) {
        handle_crash(tf);
    }

    if (trigger == IRQ_TRIGGER_LEVEL) {
        send_eoi(tf->vector);
    }

    scheduler_check_reschedule(tf);
}

// NOLINTNEXTLINE(misc-use-internal-linkage)
void x86_nmi_handler(struct interrupt_trapframe* tf) {
    per_cpu_data_t* cpu = smp_current_core();
    nmi_check_for_panic(cpu);

    struct nmi_watchdog_state* wd = &cpu->watchdog;
    uint64_t curr_ticks           = atomic_load_explicit(&wd->ticks, memory_order_relaxed);

    if (curr_ticks == wd->last_nmi_tick) {
        if (!wd->is_locked_up) {
            wd->is_locked_up = true;
            KLOG_ERROR("NMI Watchdog: CPU Core %u has Hard Locked up!\n", cpu->cpu_idx);
            handle_crash(tf);
        }
    } else {
        wd->last_nmi_tick = curr_ticks;
    }
}