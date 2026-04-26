#include <cpu/registers.h>
#include <asm.h>

.section .text.isr

EXTERN_FUNC(x86_exception_handler)
EXTERN_FUNC(x86_nmi_handler)

SYM_FUNC_START(isr_common_stub)
    cld

    PUSHA_64

    // Check if this is an NMI
    cmpq $2, X86_IFRAME_OFFSET_VECTOR(%rsp)
    je .L_nmi_stub

    // Check bottom 2 bits (RPL). If != 0, it's User Mode.
    testb $3, X86_IFRAME_OFFSET_CS(%rsp)
    jz .L_from_kernel

    // Switch GS to Kernel Per-CPU Data
    xorq %rbp, %rbp
    swapgs

.L_from_kernel:
    movq %rsp, %rdi

    FRAME_BEGIN
    call x86_exception_handler
    FRAME_END

.global isr_restore_path
isr_restore_path:
    testb $3, X86_IFRAME_OFFSET_CS(%rsp)
    jz .L_return_to_kernel

    swapgs

.L_return_to_kernel:
    POPA_64

    // Clean Stack (Remove Vector + Error Code)
    add_to_sp 16
    iretq

.L_nmi_stub:
    movq %rsp, %rdi
    movq $1, %rbx

    testb $3, X86_IFRAME_OFFSET_CS(%rsp)
    jnz .do_nmi_swap

    // Interrupted Ring 0. GS might still be User GS if we interrupted the
    // syscall path before swapgs was executed.
    READ_MSR X86_MSR_IA32_GS_BASE

    // If GS Base is Canonical Kernel address (0xffff...), sign bit is 1.
    testl %edx, %edx
    js .L_nmi_skip_swap // Already in Kernel GS, skip swap
.do_nmi_swap:
    swapgs
.L_call_nmi_handler:
    FRAME_BEGIN
    call x86_nmi_handler
    FRAME_END

    testq %rbx, %rbx
    jz .L_nmi_done
    swapgs

.L_nmi_done:
    jmp isr_restore_path

.L_nmi_skip_swap:
    xorq %rbx, %rbx // RBX = 0 signifies 'do not swapgs before returning'
    jmp .L_call_nmi_handler

SYM_FUNC_END(isr_common_stub)

.altmacro
.macro make_stub number
    .align 8
    isr_\number:
        // Push Dummy Error Code (0) if the CPU doesn't push one automatically
        .if !(\number == 8 || (\number >= 10 && \number <= 14) || \number == 17 || \number == 30)
            pushq $0
        .endif
        
        // Push Interrupt Vector Number
        pushq $\number
        jmp isr_common_stub
.endm

COMPILE_TIME_FOR 0, 256, make_stub

.macro make_entry number
    .quad isr_\number
.endm

.section .rodata
.align 8
SYM_DATA(isr_stub_table)
    COMPILE_TIME_FOR 0, 256, make_entry