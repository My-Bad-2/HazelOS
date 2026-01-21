#include "sched/syscalls.h"

#include <stdint.h>
#include <string.h>

#include "cpu/cpu.h"
#include "memory/memory.h"

static bool smap_supported = false;
static bool smep_supported = false;

static inline void stac(void) {
    if (smap_supported) {
        asm volatile("stac" ::: "memory", "cc");
    }
}

static inline void clac(void) {
    if (smap_supported) {
        asm volatile("clac" ::: "memory", "cc");
    }
}

// NOLINTNEXTLINE
void arch_syscalls_init(void) {
    smap_supported = cpu_has_feature(FEATURE_SMAP);
    smep_supported = cpu_has_feature(FEATURE_SMEP);
}

bool copy_from_user(void* dest, const void* src, size_t len) {
    if ((uintptr_t)src + len > to_higher_half(0) - 1) {
        return false;
    }

    stac();
    memcpy(dest, src, len);
    clac();

    return 0;
}