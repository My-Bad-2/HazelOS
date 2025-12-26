#ifndef KERNEL_MEMORY_MEMORY_H
#define KERNEL_MEMORY_MEMORY_H 1

#include <stdint.h>

#include "boot/boot.h"

#define PAGE_SIZE_SMALL  0x1000ul      // 4KB
#define PAGE_SIZE_MEDIUM 0x200000ul    // 2MB
#define PAGE_SIZE_LARGE  0x40000000ul  // 1GB

#ifdef __cplusplus
extern "C" {
#endif

static inline bool is_higer_half(uintptr_t addr) {
    return addr >= hhdm_request.response->offset;
}

static inline uintptr_t to_higher_half(uintptr_t addr) {
    return is_higer_half(addr) ? addr : addr + hhdm_request.response->offset;
}

static inline uintptr_t from_higher_half(uintptr_t addr) {
    return !is_higer_half(addr) ? addr : addr - hhdm_request.response->offset;
}

void memory_init();

#ifdef __cplusplus
}
#endif

#endif