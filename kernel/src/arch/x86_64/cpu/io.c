#include "cpu/io.h"

#include <stdint.h>

uint8_t io_read8(uint16_t port) {
    uint8_t ret = 0;
    asm volatile("inb %1, %0" : "=a"(ret) : "Nd"(port));
    return ret;
}

uint16_t io_read16(uint16_t port) {
    uint16_t ret = 0;
    asm volatile("inw %1, %0" : "=a"(ret) : "Nd"(port));
    return ret;
}

uint32_t io_read32(uint16_t port) {
    uint32_t ret = 0;
    asm volatile("inl %1, %0" : "=a"(ret) : "Nd"(port));
    return ret;
}

void io_write8(uint16_t port, uint8_t val) {
    asm volatile("outb %0, %1" ::"a"(val), "Nd"(port));
}

void io_write16(uint16_t port, uint16_t val) {
    asm volatile("outw %0, %1" ::"a"(val), "Nd"(port));
}

void io_write32(uint16_t port, uint32_t val) {
    asm volatile("outl %0, %1" ::"a"(val), "Nd"(port));
}