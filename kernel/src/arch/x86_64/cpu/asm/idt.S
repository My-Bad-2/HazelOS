#include <cpu/registers.h>

.section .text.isr

.extern x86_exception_handler
.extern x86_nmi_handler
.global isr_restore_path
.extern debug_print_full_frame
.type isr_common_stub, @function
isr_common_stub:
    cld

    # Save General Purpose Registers
    pushq %rax
    pushq %rbx
    pushq %rcx
    pushq %rdx
    pushq %rsi
    pushq %rdi
    pushq %rbp
    pushq %r8
    pushq %r9
    pushq %r10
    pushq %r11
    pushq %r12
    pushq %r13
    pushq %r14
    pushq %r15

    cmpq $2, X86_IFRAME_OFFSET_VECTOR(%rsp)
    je .nmi_stub

    testb $3, X86_IFRAME_OFFSET_CS(%rsp)  # Check bottom 2 bits (RPL). If != 0, it's User Mode.
    jz 1f
    xorq %rbp, %rbp
    swapgs               # Switch GS to Kernel Per-CPU Data
1:
    movq %rsp, %rdi

    pushq %rbp          # Save the RBP of the interrupted code
    movq %rsp, %rbp     # Set RBP to current stack

    call x86_exception_handler

    # Teardown the Trace frame
    leave

isr_restore_path:
    testb $3, X86_IFRAME_OFFSET_CS(%rsp)
    jz 1f
    swapgs               # Switch GS back to User TLS
1:
    # Restore Registers
    popq %r15
    popq %r14
    popq %r13
    popq %r12
    popq %r11
    popq %r10
    popq %r9
    popq %r8
    popq %rbp
    popq %rdi
    popq %rsi
    popq %rdx
    popq %rcx
    popq %rbx
    popq %rax

    # Clean Stack (Remove Vector + Error Code)
    addq $16, %rsp
    iretq
.nmi_stub:
    movq %rsp, %rdi

    movq $1, %rbx
    testb $3, X86_IFRAME_OFFSET_CS(%rsp)
    jnz .do_nmi_swap

    # We are in Ring 0, but GS might still be User GS
    movl $X86_MSR_IA32_GS_BASE, %ecx
    rdmsr

    # If GS Base is Canonical Kernel address (0xffff...), sign bit is 1.
    testl %edx, %edx
    js .nmi_skip_swap
.do_nmi_swap:
    swapgs
.call_nmi_handler:
    pushq %rbp
    movq %rsp, %rbp

    jmp .

    call x86_nmi_handler

    leave

    testq %rbx, %rbx
    jz .nmi_done
    swapgs
.nmi_done:
    jmp isr_restore_path
.nmi_skip_swap:
    xorq %rbx, %rbx
    jmp .call_nmi_handler

.macro make_stub number
    .align 8
    isr_\number:
        # Push Dummy Error Code (0) if the CPU doesn't push one automatically
        .if !(\number == 8 || (\number >= 10 && \number <= 14) || \number == 17 || \number == 30)
            pushq $0
        .endif
        
        # Push Interrupt Vector Number
        pushq $\number
        jmp isr_common_stub
.endm

.macro make_entry number
    .quad isr_\number
.endm

.section .text
.altmacro

.set i, 0
.rept 256
    make_stub %i
    .set i, i + 1
.endr

.section .data
.align 8
.global isr_stub_table
isr_stub_table:
    .set i, 0
    .rept 256
        make_entry %i
        .set i, i + 1
    .endr