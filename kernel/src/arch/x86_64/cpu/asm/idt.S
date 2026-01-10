.section .text.isr

.extern x86_exception_handler
.global isr_restore_path
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

    testb $3, 144(%rsp)  # Check bottom 2 bits (RPL). If != 0, it's User Mode.
    jz 1f
    swapgs               # Switch GS to Kernel Per-CPU Data
1:
    movq %rsp, %rdi

    pushq %rbp          # Save the RBP of the interrupted code
    movq %rsp, %rbp     # Set RBP to current stack

    call x86_exception_handler

    # Teardown the Trace frame
    leave

isr_restore_path:
    testb $3, 144(%rsp)
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