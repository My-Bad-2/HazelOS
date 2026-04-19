#include "cpu/simd.h"

#include <stdint.h>
#include <string.h>

#include "cpu/cpu.h"
#include "cpu/registers.h"
#include "libs/log.h"
#include "libs/math.h"
#include "memory/heap.h"

static enum {
    FPU_NONE = 0,
    FPU_SSE,
    FPU_AVX,
    FPU_AVXOPT,
} fpu_mode = FPU_NONE;

static size_t save_size     = 0;
static void* clean_state    = nullptr;
static bool warned_no_state = false;

static inline void fxsave(void* buffer) {
    asm volatile("fxsave (%0)" ::"r"(buffer) : "memory");
}

static inline void fxrstor(void* buffer) {
    asm volatile("fxrstor (%0)" ::"r"(buffer) : "memory");
}

static inline void xsave(void* buffer) {
    constexpr uint32_t low  = 0xFFFFFFFF;
    constexpr uint32_t high = 0xFFFFFFFF;
    asm volatile("xsave (%0)" ::"r"(buffer), "a"(low), "d"(high) : "memory");
}

static inline void xrstor(void* buffer) {
    constexpr uint32_t low  = 0xFFFFFFFF;
    constexpr uint32_t high = 0xFFFFFFFF;
    asm volatile("xrstor (%0)" ::"r"(buffer), "a"(low), "d"(high) : "memory");
}

static inline void xsaveopt(void* buffer) {
    constexpr uint32_t low  = 0xFFFFFFFF;
    constexpr uint32_t high = 0xFFFFFFFF;
    asm volatile("xsaveopt (%0)" ::"r"(buffer), "a"(low), "d"(high) : "memory");
}

void simd_init(void) {
    const bool has_sse      = cpu_has_feature(FEATURE_SSE);
    const bool has_xsave    = cpu_has_feature(FEATURE_XSAVE);
    const bool has_avx      = cpu_has_feature(FEATURE_AVX);
    const bool has_avx512f  = cpu_has_feature(FEATURE_AVX512F);
    const bool has_xsaveopt = cpu_has_subfeature(FEATURE_XSAVEOPT);

    if (!has_sse) {
        fpu_mode = FPU_NONE;
        KLOG_WARN("SIMD: SSE not supported; disabling FPU context switching\n");
        return;
    }

    uint64_t cr0 = read_cr0();
    cr0 &= ~X86_CR0_EM;
    cr0 |= X86_CR0_MP;
    cr0 |= X86_CR0_NE;
    write_cr0(cr0);

    uint64_t cr4 = read_cr4();
    cr4 |= X86_CR4_OSFXSR;
    cr4 |= X86_CR4_OSXMMEXPT;
    write_cr4(cr4);

    uint32_t mxcsr = read_mxcsr();
    mxcsr |= X86_MXCSR_IM;
    mxcsr |= X86_MXCSR_DM;
    mxcsr |= X86_MXCSR_ZM;
    mxcsr |= X86_MXCSR_OM;
    mxcsr |= X86_MXCSR_UM;
    mxcsr |= X86_MXCSR_PM;
    write_mxcsr(mxcsr);

    fpu_mode  = FPU_SSE;
    save_size = 512;

    if (!has_xsave || !has_avx) {
        KLOG_WARN(
            "SIMD: XSAVE/AVX not fully supported (xsave=%d avx=%d), using SSE mode\n",
            has_xsave,
            has_avx
        );

        goto cleanup;
    }

    cr4 = read_cr4();
    cr4 |= X86_CR4_OSXSAVE;
    write_cr4(cr4);

    {
        uint64_t xcr0 = read_xcr0();

        cpuid_registers_t regs = cpu_read_value(0xD);

        uint32_t mask_low  = regs.eax;
        uint32_t mask_high = regs.edx;
        uint64_t mask      = ((uint64_t)mask_high << 32) | mask_low;

        xcr0 |= X86_XCR0_X87;
        xcr0 |= X86_XCR0_SSE;
        xcr0 |= X86_XCR0_AVX;

        if (has_avx512f) {
            xcr0 |= X86_XCR0_OPMASK;
            xcr0 |= X86_XCR0_ZMM_Hi256;
            xcr0 |= X86_XCR0_Hi_ZMM;
        }

        xcr0 &= mask;

        write_xcr0(xcr0);

        if (xcr0 & X86_XCR0_AVX) {
            fpu_mode = has_xsaveopt ? FPU_AVXOPT : FPU_AVX;
        }

        save_size = align_up(regs.ecx, 64);
    }

cleanup:
    asm volatile("fninit");

    if (!clean_state) {
        size_t size = simd_get_save_size();

        clean_state = kmalloc(size);

        if (!clean_state) PANIC("SIMD: Cannot allocate clean state buffer!\n");

        memset(clean_state, 0, size);
        simd_save(clean_state);
    }
}

void simd_save(void* buffer) {
    switch (fpu_mode) {
        case FPU_AVXOPT:
            xsaveopt(buffer);
            break;
        case FPU_AVX:
            xsave(buffer);
            break;
        case FPU_SSE:
            fxsave(buffer);
            break;
        case FPU_NONE:
        default:
            if (!warned_no_state) {
                warned_no_state = true;
                KLOG_WARN("SIMD: save requested with no FPU state initialized\n");
            }

            break;
    }
}

void simd_restore(void* buffer) {
    switch (fpu_mode) {
        case FPU_AVXOPT:
        case FPU_AVX:
            xrstor(buffer);
            break;
        case FPU_SSE:
            fxrstor(buffer);
            break;
        case FPU_NONE:
        default:
            if (!warned_no_state) {
                warned_no_state = true;
                KLOG_WARN("SIMD: restore requested with no FPU state initialized\n");
            }

            break;
    }
}

void* simd_get_clean_state(void) {
    return clean_state;
}

size_t simd_get_save_size(void) {
    return save_size;
}