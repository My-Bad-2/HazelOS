#ifndef KERNEL_CPU_PIC_H
#define KERNEL_CPU_PIC_H 1

#include <stdint.h>

#include "cpu/exception.h"

#ifdef __cplusplus
extern "C" {
#endif

void pic_init(void);
void pic_disable(void);

void pic_send_eoi(uint8_t irq);
void pic_configure_irq(uint8_t irq, bool mask, irq_trigger_mode_t mode);

#ifdef __cplusplus
}
#endif

#endif