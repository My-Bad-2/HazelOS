#ifndef KERNEL_ARCH_H
#define KERNEL_ARCH_H 1

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

void arch_pause(void);
void arch_disable_interrupts(void);
void arch_enable_interrupts(void);
void arch_halt(bool interrupts);
size_t arch_save_flags(void);
void arch_restore_flags(size_t flags);

void arch_write(const char* str, size_t len);
void arch_writec(char ch);

void arch_serial_init(void);
void arch_init(void);

#ifdef __cplusplus
}
#endif

#endif