#include "arch.h"

#include <stddef.h>

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

void arch_serial_init(void) {
    drivers_uart_init(COM_PORT1, 115200);
}

void arch_init(void) {}