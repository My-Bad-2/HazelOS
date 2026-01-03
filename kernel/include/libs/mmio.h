#ifndef KERNEL_LIBS_MMIO_H
#define KERNEL_LIBS_MMIO_H 1

#include <stdatomic.h>
#include <stdint.h>

#include "libs/math.h"

static inline void mmio_write8(void* addr, uint8_t val) {
    atomic_thread_fence(memory_order_seq_cst);
    *(volatile uint8_t*)addr = val;
    atomic_thread_fence(memory_order_seq_cst);
}

static inline void mmio_write16(void* addr, uint16_t val) {
    atomic_thread_fence(memory_order_seq_cst);
    *(volatile uint16_t*)addr = val;
    atomic_thread_fence(memory_order_seq_cst);
}

static inline void mmio_write32(void* addr, uint32_t val) {
    atomic_thread_fence(memory_order_seq_cst);
    *(volatile uint32_t*)addr = val;
    atomic_thread_fence(memory_order_seq_cst);
}

static inline void mmio_write64(void* addr, uint64_t val) {
    atomic_thread_fence(memory_order_seq_cst);
    *(volatile uint64_t*)addr = val;
    atomic_thread_fence(memory_order_seq_cst);
}

static inline uint8_t mmio_read8(void* addr) {
    uint8_t val = *(volatile uint8_t*)addr;
    atomic_thread_fence(memory_order_seq_cst);
    return val;
}

static inline uint16_t mmio_read16(void* addr) {
    uint16_t val = *(volatile uint16_t*)addr;
    atomic_thread_fence(memory_order_seq_cst);
    return val;
}

static inline uint32_t mmio_read32(void* addr) {
    uint32_t val = *(volatile uint32_t*)addr;
    atomic_thread_fence(memory_order_seq_cst);
    return val;
}

static inline uint64_t mmio_read64(void* addr) {
    uint64_t val = *(volatile uint64_t*)addr;
    atomic_thread_fence(memory_order_seq_cst);
    return val;
}

#endif