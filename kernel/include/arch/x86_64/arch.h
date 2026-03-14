#ifndef KERNEL_ARCH_H
#define KERNEL_ARCH_H 1

#include <stddef.h>
#include <stdint.h>

#define TARGET_UART        1
#define TARGET_FRAMEBUFFER 2

#ifdef __cplusplus
extern "C" {
#endif

void arch_pause(void);
void arch_disable_interrupts(void);
void arch_enable_interrupts(void);
[[noreturn]] void arch_halt(bool interrupts);

size_t arch_save_flags(void);
void arch_restore_flags(size_t flags);

uint32_t arch_get_core_idx(void);
uint64_t arch_get_random_bytes(void);

void arch_write(int target, const char* str);
void arch_writec(int target, char ch);

void arch_serial_init(void);
void arch_init(void);

#ifdef __cplusplus
}
#endif

#endif