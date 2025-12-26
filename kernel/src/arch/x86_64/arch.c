#include "arch.h"

#include <stddef.h>
#include <stdint.h>

#include "compiler.h"
#include "drivers/uart.h"

void arch_disable_interrupts(void) {
    asm volatile("cli");
}

void arch_enable_interrupts(void) {
    asm volatile("sti");
}

void arch_pause(void) {
    asm volatile("sti");
}

void arch_write(const char* str) {
    if (unlikely(!str)) {
        return;
    }

    for (size_t i = 0; str[i] != '\0'; ++i) {
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
        "pushfq;"
        "popq %0"
        : "=r"(rflags)
    );

    return rflags;
}

void arch_restore_flags(size_t flags) {
    asm volatile(
        "pushq %0;"
        "popfq;" ::"r"(flags)
    );
}

uint32_t arch_get_core_idx(void) {
    // Until SMP is initialized, we're running on BSP
    return 0;
}

void arch_serial_init(void) {
    drivers_uart_init(COM_PORT1, 115200);
}

void arch_init(void) {}