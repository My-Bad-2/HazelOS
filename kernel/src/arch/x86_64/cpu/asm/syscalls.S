#include <cpu/registers.h>
#include <asm.h>
#include <core/errors.h>

#define USER_CS 0x2B
#define USER_SS 0x23

.section .text

EXTERN_FUNC(syscall_dispatcher)
SYM_FUNC_START(syscall_entry)
    swapgs

    movq %rsp, %gs:32 // Save user rsp
    movq %gs:24, %rsp // Load kernel rsp

    // Tell the unwinder that RSP has completely changed.
    .cfi_def_cfa %rsp, 0

    SMP_RMB()

    push_value $USER_SS // ss
    push_value %gs:32   // rsp
    push_reg %r11       // rflags
    push_value $USER_CS // cs
    push_reg %rcx       // rip

    // Simulate the ISR stub pushes
    push_value $0
    push_value $0x80

    PUSHA_64
    
    movq %rsp, %rdi // Pass trapframe to syscall_dispatcher
    cld
    call syscall_dispatcher
    cli // Disable Interrupts for safe context restoration

SYM_FUNC_END(syscall_entry)

SYM_FUNC_START(syscall_restore_path)
    POPA_64
    
    add_to_sp 16
    pop_reg %rcx    // Pop rip into rcx for sysret
    add_to_sp 8     // Discard cs
    pop_reg %r11    // Pop rflags into r11 for sysret
    pop_reg %rsp    // Pop rsp directly to the stack pointer

    // SS is discarded as we overwrite RSP and swapgs

    swapgs
    sysretq
SYM_FUNC_END(syscall_restore_path)

SYM_FUNC_START(syscall_compat_entry)
    movq $ERR_DENIED, %rax
    sysret
SYM_FUNC_END(syscall_compat_entry)