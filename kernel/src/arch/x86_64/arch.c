#include "arch.h"

#include <stddef.h>

#include "compiler.h"
#include "cpu/cpu.h"
#include "drivers/term.h"
#include "drivers/tsc.h"
#include "drivers/uart.h"

#define MIX_K1 0xff51afd7ed558ccdul
#define MIX_K2 0xc4ceb9fe1a85ec53ul

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

    if (term_is_initialized()) {
        term_write(str);
    } /* else { */
    for (size_t i = 0; str[i] != '\0'; ++i) {
        drivers_uart_writec(COM_PORT1, str[i]);
    }
    // }
}

void arch_writec(char ch) {
    drivers_uart_writec(COM_PORT1, ch);
}

void arch_halt(bool interrupts) {
    if (!interrupts) {
        arch_disable_interrupts();
    } else {
        arch_enable_interrupts();
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

static inline int rdseed_read(uint64_t* dest) {
    char success = 0;

    asm volatile(
        "rdseed %0\n\t"
        "setc %1"
        : "=r"(*dest), "=qm"(success)::"cc"
    );

    return success;
}

static inline int rdrand_read(uint64_t* dest) {
    char success = 0;

    asm volatile(
        "rdrand %0\n\t"
        "setc %1"
        : "=r"(*dest), "=qm"(success)::"cc"
    );

    return success;
}

uint64_t arch_get_random_bytes(void) {
    uint64_t rand_val = 0;
    uint64_t tsc_val  = tsc_read();

    int success = 0;
    for (int i = 0; i < 20 && !success; ++i) {
        success = rdseed_read(&rand_val);

        if (!success) {
            arch_pause();
        }
    }

    if (!success) {
        for (int i = 0; i < 10 && !success; ++i) {
            success = rdrand_read(&rand_val);
        }
    }

    if (!success) {
        rand_val = tsc_val;
    }

    uint64_t combined = rand_val ^ tsc_val;
    combined ^= (combined >> 33);
    combined *= MIX_K1;
    combined ^= (combined >> 33);
    combined *= MIX_K2;
    combined ^= (combined >> 33);

    return combined;
}

void arch_serial_init(void) {
    drivers_uart_init(COM_PORT1, 115200);
    cpu_read_features();
}

void arch_init(void) {}