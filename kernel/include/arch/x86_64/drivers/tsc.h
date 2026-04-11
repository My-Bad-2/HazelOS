#ifndef KERNEL_DRIVERS_TSC_H
#define KERNEL_DRIVERS_TSC_H 1

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

static inline uint64_t tsc_read(void) {
    uint32_t lo = 0;
    uint32_t hi = 0;

    asm volatile(
        "lfence\n\t"
        "rdtsc"
        : "=a"(lo), "=d"(hi)
    );

    return ((uint64_t)hi << 32) | lo;
}

#ifdef __cplusplus
}
#endif

#endif