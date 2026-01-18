#include <cpu/registers.h>

.section .text

.global syscall_entry
.extern syscall_dispatcher
.type syscall_entry, @function
syscall_entry:
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
    # %rcx = ARG4
    # %r8  = ARG5
    # %r9  = ARG6
    # Userspace sends: %rdi, %rsi, %rdx, %r10, %r8, %r9
    # SYSCALL destroyed %rcx, so userspace puts ARG4 in %r10

    # Now we fix it
    movq %r10, %rcx
    
    movq %rax, %rsi # Syscall number
    movq %rsp, %rdi # Pointer to the stack frame

    sti
    call syscall_dispatcher
    cli

    movq %rax, 96(%rsp)

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
    popq %rsp

    swapgs
    sysretq

.global syscall_compat_entry
.type syscall_compat_entry, @function
syscall_compat_entry:
    movq $-38, %rax
    sysret
