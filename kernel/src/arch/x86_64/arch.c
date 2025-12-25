#include <stddef.h>

#include "arch.h"
#include "compiler.h"
#include "drivers/uart.h"

[[gnu::naked]]
void arch_disable_interrupts(void) {
    asm volatile("cli");
}

[[gnu::naked]]
void arch_enable_interrupts(void) {
    asm volatile("sti");
}

[[gnu::naked]]
void arch_pause(void) {
    asm volatile("sti");
}

void arch_write(const char* str, size_t len) {
    if (unlikely(!str)) {
        return;
    }

    for (size_t i = 0; i < len; ++i) {
        drivers_uart_writec(COM_PORT1, str[i]);
    }
}

void arch_writec(char ch) {
    drivers_uart_writec(COM_PORT1, ch);
}

void arch_halt(bool interrupts) {
    if (!interrupts) {
        arch_disable_interrupts();
    }

    while (true) {
        asm volatile("hlt");
    }
}

size_t arch_save_flags(void) {
    size_t rflags = 0;

    asm volatile(
        "pushfq\n\t"
        "popq %0\n\t"
        : "=r"(rflags)
    );

    return rflags;
}

void arch_restore_flags(size_t flags) {
    asm volatile(
        "pushq %0\n\t"
        "popfq\n\t" ::"r"(flags)
    );
}

void arch_serial_init(void) {
    drivers_uart_init(COM_PORT1, 115200);
}

void arch_init(void) {}