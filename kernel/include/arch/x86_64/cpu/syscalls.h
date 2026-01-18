#ifndef KERNEL_CPU_SYSCALLS_H
#define KERNEL_CPU_SYSCALLS_H 1

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    uint64_t rbx;
    uint64_t rdx;
    uint64_t rsi;
    uint64_t rdi;
    uint64_t r8;
    uint64_t r9;
    uint64_t r10;  // Holds 4th arg
    uint64_t r12;
    uint64_t r13;
    uint64_t r14;
    uint64_t r15;
    uint64_t rbp;
    uint64_t rax;

    uint64_t rip;     // User Return Address
    uint64_t rflags;  // User Flags
    uint64_t rsp;     // User Stack Pointer
} syscall_regs_t;

void syscall_init(void);

#ifdef __cplusplus
}
#endif

#endif