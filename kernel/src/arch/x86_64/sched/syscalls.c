#include "core/syscalls.h"

#include <stdint.h>
#include <string.h>

#include "compiler.h"
#include "core/errors.h"
#include "cpu/cpu.h"
#include "memory/vmm.h"

static bool smap_supported = false;
static bool smep_supported = false;

static inline void stac(void) {
    if (smap_supported) asm volatile("stac" ::: "memory", "cc");
}

static inline void clac(void) {
    if (smap_supported) asm volatile("clac" ::: "memory", "cc");
}

// NOLINTNEXTLINE
void arch_syscalls_init(void) {
    smap_supported = cpu_has_feature(FEATURE_SMAP);
    smep_supported = cpu_has_feature(FEATURE_SMEP);
}

static inline int access_ok(const void* addr, size_t len) {
    const uintptr_t uaddr = (uintptr_t)addr;
    if (uaddr >= get_kernel_space_start_limit() || (uaddr + len >= get_kernel_space_end_limit()))
        return false;
    return true;
}

int copy_from_user(void* dest, const void* src, size_t len) {
    if (unlikely(!access_ok(src, len))) return ERR_INVALID;

    stac();
    memcpy(dest, src, len);
    clac();

    return ERR_OK;
}

int copy_to_user(void* dest, const void* src, size_t len) {
    if (unlikely(!access_ok(src, len))) return ERR_INVALID;

    stac();
    memcpy(dest, src, len);
    clac();

    return ERR_OK;
}