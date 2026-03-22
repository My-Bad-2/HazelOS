#include <cpu/registers.h>

.section .text

.global syscall_entry
.global syscall_restore_path
.extern syscall_dispatcher
.type syscall_entry, @function
syscall_entry:
    cld
    swapgs

    movq %rsp, %gs:32
    movq %gs:24, %rsp

    # Preserve registers for sysv abi and rcx/r11 ( User return info)
    pushq %gs:32    # User RSP
    pushq %r11      # User RFLAGS
    pushq %rcx      # User RIP

    # Push General Purpose Registers (Callee-saved + Arguments)
    pushq %rax
    pushq %rbp
    pushq %r15
    pushq %r14
    pushq %r13
    pushq %r12
    pushq %r10
    pushq %r9
    pushq %r8
    pushq %rdi
    pushq %rsi
    pushq %rdx
    pushq %rbx

    # %rdi = ARG1
    # %rsi = ARG2
    # %rdx = ARG3
    # %r10 = ARG4
    # %r8  = ARG5
    # %r9  = ARG6
    
    movq %rax, %rsi # Syscall number
    movq %rsp, %rdi # Pointer to the stack frame

    sti
    call syscall_dispatcher
    cli

    movq %rax, 96(%rsp)

.global syscall_restore_path
.type syscall_restore_path, @function
syscall_restore_path:
    popq %rbx
    popq %rdx
    popq %rsi
    popq %rdi
    popq %r8
    popq %r9
    popq %r10
    popq %r12
    popq %r13
    popq %r14
    popq %r15
    popq %rbp
    popq %rax

    popq %rcx
    popq %r11
    
    cli
    popq %rsp

    swapgs
    sysretq

.global syscall_compat_entry
.type syscall_compat_entry, @function
syscall_compat_entry:
    movq $-38, %rax
    sysret
