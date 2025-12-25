#ifndef KERNEL_ARCH_H
#define KERNEL_ARCH_H

#ifdef __cplusplus
extern "C" {
#endif

void arch_pause(void);
void arch_disable_interrupts(void);
void arch_enable_interrupts(void);
void arch_halt(bool interrupts);

void arch_init(void);

#ifdef __cplusplus
}
#endif

#endif