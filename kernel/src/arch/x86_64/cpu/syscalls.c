#include "cpu/syscalls.h"

#include <stdint.h>

#include "cpu/cpu.h"
#include "cpu/gdt.h"
#include "cpu/registers.h"
#include "libs/log.h"

// AMD64 Technology 24593—Rev. 3.42—March 2024 Pg. no. 175 System Instructions
#define STAR_SET_KERNEL_BASE(base) ((uint64_t)(base) << 32)
#define STAR_SET_USER_BASE(base)   ((uint64_t)(base) << 48)

extern void syscall_entry(void);
extern void syscall_compat_entry(void);

void syscall_init(void) {
    if (!cpu_has_feature(FEATURE_SYSCALL)) {
        PANIC("SYSCALL: CPU does not support SYSCALL/SYSRET.");
    }

    uint64_t efer = read_msr(X86_MSR_IA32_EFER);

    if (!(efer & X86_EFER_SCE)) {
        write_msr(X86_MSR_IA32_EFER, efer | X86_EFER_SCE);
    }

    uint64_t star = STAR_SET_KERNEL_BASE(KERNEL_CODE);
    star |= STAR_SET_USER_BASE(USER_CODE32 | 3);

    write_msr(X86_MSR_IA32_STAR, star);

    // LSTAR: The 64-bit entry point for syscalls
    write_msr(X86_MSR_IA32_LSTAR, (uint64_t)syscall_entry);
    // CSTAR: The 32-bit entry point for syscalls
    write_msr(X86_MSR_IA32_CSTAR, (uint64_t)syscall_compat_entry);

    uint64_t mask = X86_FLAGS_IF | X86_FLAGS_DF | X86_FLAGS_TF | X86_FLAGS_CF | X86_FLAGS_PF |
                    X86_FLAGS_AF | X86_FLAGS_ZF | X86_FLAGS_SF | X86_FLAGS_OF;

    write_msr(X86_MSR_IA32_FMASK, mask);
}

// NOLINTNEXTLINE(misc-use-internal-linkage)
uint64_t syscall_dispatcher(syscall_regs_t*, uint64_t num) {
    KLOG_DEBUG("Syscall %lu called!\n", num);

    return 0;
}