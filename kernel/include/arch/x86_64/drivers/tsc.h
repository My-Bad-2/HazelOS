#ifndef KERNEL_DRIVERS_TSC_H
#define KERNEL_DRIVERS_TSC_H 1

#include <stddef.h>
#include <stdint.h>

#include "cpu/cpu.h"

#ifdef __cplusplus
extern "C" {
#endif

static inline uint64_t tsc_read(void) {
    uint32_t lo = 0;
    uint32_t hi = 0;

    if (cpu_has_feature(FEATURE_RDTSCP)) {
        asm volatile("rdtscp" : "=a"(lo), "=d"(hi)::"memory", "ecx");
    } else {
        asm volatile(
            "lfence\n\t"
            "rdtsc"
            : "=a"(lo), "=d"(hi)
        );
    }

    return ((uint64_t)hi << 32) | lo;
}

void tsc_init(void);
bool tsc_is_invarient(void);

void tsc_mdelay(uint64_t ms);
void tsc_udelay(uint64_t us);
void tsc_ndelay(uint64_t ns);

uint64_t tsc_get_uptime_ns(void);
uint64_t tsc_get_uptime_us(void);
uint64_t tsc_get_uptime_ms(void);
uint64_t tsc_get_hz(void);

void tsc_sync_bsp(void);
void tsc_sync_ap(void);

#ifdef __cplusplus
}
#endif

#endif