#ifndef KERNEL_CPU_IO_H
#define KERNEL_CPU_IO_H 1

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

uint8_t io_read8(uint16_t port);
uint16_t io_read16(uint16_t port);
uint32_t io_read32(uint16_t port);

void io_write8(uint16_t port, uint8_t val);
void io_write16(uint16_t port, uint16_t val);
void io_write32(uint16_t port, uint32_t val);

static inline void io_wait(void) {
    // Use port 0x80 for a teeny-tiny delay
    io_write8(0x80, 0);
}

#ifdef __cplusplus
}
#endif

#endif