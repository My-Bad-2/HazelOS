#include "core/syscalls.h"

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

static inline int access_ok(const void* addr, size_t len) {
    uintptr_t uaddr      = (uintptr_t)addr;
    uintptr_t user_limit = to_higher_half(0);

    return (uaddr < user_limit) && (len <= (user_limit - uaddr));
}

size_t copy_from_user(void* dest, const void* src, size_t len) {
    if (!access_ok(src, len)) {
        return len;
    }

    stac();
    memcpy(dest, src, len);
    clac();

    return 0;
}

size_t copy_to_user(void* dest, const void* src, size_t len) {
    if (!access_ok(dest, len)) {
        return len;
    }

    stac();
    memcpy(dest, src, len);
    clac();

    return 0;
}