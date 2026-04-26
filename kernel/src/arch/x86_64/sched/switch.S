#include <asm.h>

.section .text

/** =========================================================
 * void kernel_thread_entry(void);
 * ---------------------------------------------------------
 * Argument:
 *   %rdi = kstack->args
 *   %rsi = kstack->entry
 * ========================================================= */
SYM_FUNC_START(kernel_thread_entry)
    sti
    pop_value %rdi   // Load argument
    pop_value %rax   // Load function pointer

    // Safely execute the kernel function
    CALL_NOSPEC %rax
    
    // If the kernel thread function accidentally returns, kill it
    call thread_exit
1:
    hlt
    jmp 1b
SYM_FUNC_END(kernel_thread_entry)

/** =========================================================
 * void arch_switch_context(switch_context_t** prev, switch_context_t* next);
 * ---------------------------------------------------------
 * Argument:
 *   %rdi = previous switch context
 *   %rsi = next switch context
 * ========================================================= */
SYM_FUNC_START(arch_switch_context)
    // Save current thread's callee-preserved context
    push_reg %rbx
    push_reg %rbp
    push_reg %r12
    push_reg %r13
    push_reg %r14
    push_reg %r15

    // The actual context switch
    movq %rsp, (%rdi) // *(&curr->context_rsp) = RSP
    movq %rsi, %rsp   // Load the new RSP from RSI

    // Restore the next thread's callee-preserved context
    pop_reg %r15
    pop_reg %r14
    pop_reg %r13
    pop_reg %r12
    pop_reg %rbp
    pop_reg %rbx
    RET_AND_SPECULATION_POSTFENCE
SYM_FUNC_END(arch_switch_context)