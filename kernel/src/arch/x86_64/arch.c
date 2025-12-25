#include "arch.h"

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

void arch_halt(bool interrupts) {
    if (!interrupts) {
        arch_disable_interrupts();
    }

    while (true) {
        asm volatile("hlt");
    }
}

void arch_init(void) {}