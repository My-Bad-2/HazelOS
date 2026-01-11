.section .text

# =========================================================
# void kernel_thread_entry(void);
# ---------------------------------------------------------
# Argument:
#   %rdi = kstack->args
#   %rsi = kstack->entry
# =========================================================
.global kernel_thread_entry
.type kernel_thread_entry, @function
kernel_thread_entry:
    sti
    popq %rdi   # Load argument
    popq %rax   # Load function pointer
    call *%rax  # Execute Kernel function
    call thread_exit # If function returns, kill thread
    hlt

# =========================================================
# void arch_switch_context(switch_context_t** prev, switch_context_t* next);
# ---------------------------------------------------------
# Argument:
#   %rdi = previous switch context
#   %rsi = next switch context
# =========================================================
.global arch_switch_context
.type arch_switch_context, @function
.align 16
arch_switch_context:
    # Save current context
    pushq %rbx
    pushq %rbp
    pushq %r12
    pushq %r13
    pushq %r14
    pushq %r15

    movq %rsp, (%rdi) # *(&curr->context_rsp) = RSP
    movq %rsi, %rsp # Load the new RSP from RSI

    # Restore next context
    popq %r15
    popq %r14
    popq %r13
    popq %r12
    popq %rbp
    popq %rbx
    ret