#ifndef KERNEL_CPU_SYSCALLS_H
#define KERNEL_CPU_SYSCALLS_H 1

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

struct syscall_regs {
    uint64_t rbx;
    uint64_t rdx;  // 3rd argument
    uint64_t rsi;  // 2nd argument
    uint64_t rdi;  // 1st argument
    uint64_t r8;   // 5th argument
    uint64_t r9;   // 6th argument
    uint64_t r10;  // 4th argument
    uint64_t r12;
    uint64_t r13;
    uint64_t r14;
    uint64_t r15;
    uint64_t rbp;
    uint64_t rax;

    uint64_t rip;     // User Return Address
    uint64_t rflags;  // User Flags
    uint64_t rsp;     // User Stack Pointer
};

void syscall_init(void);

#ifdef __cplusplus
}
#endif

#endif