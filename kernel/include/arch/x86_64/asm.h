#ifndef ARCH_ASM_H
#define ARCH_ASM_H 1

// clang-format off
#ifdef __ASSEMBLER__

#define SYM_FUNC_START(name) \
    .align 16; \
    .global name; \
    .type name, @function; \
name: \
    .cfi_startproc

#define SYM_FUNC_END(name) \
    .cfi_endproc; \
    .size name, . - name

#define SYM_FUNC_START_LOCAL(name) \
    .align 16; \
    .type name, @function; \
    name: \
    .cfi_startproc

#define SYM_DATA(name) \
    .global name; \
    .type name, @object; \
    name:

// Declares a weak function. If another function with the same name exists elsewhere,
// the linker will use that one instead of throwing a duplicate symbol error.
#define SYM_FUNC_START_WEAK(name) \
    .align 16; \
    .weak name; \
    .type name, @function; \
    name: \
    .cfi_startproc

// Places the function in the .text.unlikely section. This tells the linker
// to move it away from the hot code paths, improving instruction cache density.
#define SYM_FUNC_START_COLD(name) \
    .section .text.unlikely, "ax"; \
    .align 16; \
    .global name; \
    .type name, @function; \
    name: \
    .cfi_startproc

#define LOCK_PREFIX lock;

.macro ATOMIC_ADD ptr_reg, val_reg
    LOCK_PREFIX
    addq \val_reg, (\ptr_reg)
.endm

.macro ATOMIC_DEC ptr_reg
    LOCK_PREFIX
    decq (\ptr_reg)
.endm

// Input: msr_id in %rcx. Output: High 32 bits in %edx, Low 32 bits in %eax 
.macro READ_MSR msr_id
    movl \msr_id, %ecx
    rdmsr
.endm

.macro WRITE_MSR msr_id
    movl \msr_id, %ecx
    wrmsr
.endm

.macro RELOAD_CR3
    movq %cr3, %rax
    movq %rax, %cr3
.endm

// Sets 'count' bytes at 'dest' to 'val' (lower 8 bits of val).
.macro HW_MEMSET dest_reg, val_reg, count_reg
    movq \dest_reg, %rdi
    movq \val_reg, %rax
    movq \count_reg, %rcx
    rep stosb
.endm

// Copies 'count' bytes from 'src' to 'dest'.
.macro HW_MEMCPY dest_reg, src_reg, count_reg
    movq \dest_reg, %rdi
    movq \src_reg, %rsi
    movq \count_reg, %rcx
    rep movsb
.endm

.macro push_reg reg
    pushq \reg
    .cfi_adjust_cfa_offset 8
.endm

.macro pop_reg reg
    popq \reg
    .cfi_adjust_cfa_offset - 8
    .cfi_restore \reg
.endm

.macro push_value value
    pushq \value
    .cfi_adjust_cfa_offset 8
.endm

.macro pop_value value
    popq \value
    .cfi_adjust_cfa_offset -8
.endm

.macro sub_from_sp value
    sub $\value, %rsp
    .cfi_adjust_cfa_offset \value
.endm

.macro add_to_sp value
    add $\value, %rsp
    .cfi_adjust_cfa_offset -\value
.endm

.macro PUSHA_64
    push_reg %rax
    push_reg %rbx
    push_reg %rcx
    push_reg %rdx
    push_reg %rsi
    push_reg %rdi
    push_reg %rbp
    push_reg %r8
    push_reg %r9
    push_reg %r10
    push_reg %r11
    push_reg %r12
    push_reg %r13
    push_reg %r14
    push_reg %r15
.endm

.macro POPA_64
    pop_reg %r15
    pop_reg %r14
    pop_reg %r13
    pop_reg %r12
    pop_reg %r11
    pop_reg %r10
    pop_reg %r9
    pop_reg %r8
    pop_reg %rbp
    pop_reg %rdi
    pop_reg %rsi
    pop_reg %rdx
    pop_reg %rcx
    pop_reg %rbx
    pop_reg %rax
.endm

.macro FRAME_BEGIN
#if CONFIG_FRAME_POINTER
    pushq %rbp
    .cfi_adjust_cfa_offset 8
    .cfi_rel_offset %rbp, 0
    movq %rsp, %rbp
    .cfi_def_cfa_register %rbp
#endif
.endm

.macro FRAME_END
#if CONFIG_FRAME_POINTER
    popq %rbp
    .cfi_def_cfa %rsp, 8
    .cfi_restore %rbp
#endif
.endm

#define ALL_CFI_SAME_VALUE  \
    .cfi_same_value %rax;   \
    .cfi_same_value %rbx;   \
    .cfi_same_value %rcx;   \
    .cfi_same_value %rdx;   \
    .cfi_same_value %rsi;   \
    .cfi_same_value %rdi;   \
    .cfi_same_value %rbp;   \
    .cfi_same_value %r8 ;   \
    .cfi_same_value %r9 ;   \
    .cfi_same_value %r10;   \
    .cfi_same_value %r11;   \
    .cfi_same_value %r12;   \
    .cfi_same_value %r13;   \
    .cfi_same_value %r14;   \
    .cfi_same_value %r15

#define ALL_CFI_UNDEFINED   \
    .cfi_undefined %rax;    \
    .cfi_undefined %rbx;    \
    .cfi_undefined %rcx;    \
    .cfi_undefined %rdx;    \
    .cfi_undefined %rsi;    \
    .cfi_undefined %rdi;    \
    .cfi_undefined %rbp;    \
    .cfi_undefined %r8 ;    \
    .cfi_undefined %r9 ;    \
    .cfi_undefined %r10;    \
    .cfi_undefined %r11;    \
    .cfi_undefined %r12;    \
    .cfi_undefined %r13;    \
    .cfi_undefined %r14;    \
    .cfi_undefined %r15

#define EXTERN_FUNC(_x) \
    .extern _x

#define RET_AND_SPECULATION_POSTFENCE \
    ret; \
    int3

#define JMP_AND_SPECULATION_POSTFENCE(_x) \
    jmp _x; \
    int3

// Repoline mitigation for indirect calls
// Usage: CALL_NOSPEC %rax
.macro CALL_NOSPEC reg
    call    999f
    int3
999:
    movq    \reg, (%rsp)
    RET_AND_SPECULATION_POSTFENCE
.endm

// Repoline mitigation for indirect calls
// Usage: CALL_NOSPEC %rax
.macro CALL_NOSPEC_NORET reg
    call    999f
    int3
999:
    movq    \reg, (%rsp)
.endm

// Retpoline mitigation for indirect jumps
.macro JMP_NOSPEC reg
    call    999f
    int3
999:
    movq    \reg, (%rsp)
    RET_AND_SPECULATION_POSTFENCE
.endm

// Prevents the CPU from reordering memory reads/writes across this point
#define SMP_MB()  mfence
// Prevents the CPU from reordering memory reads across this point
#define SMP_RMB() lfence
// Prevents the CPU from reordering memory writes across this point
#define SMP_WMB() sfence

#define PAGE_SIZE 0x1000
#define L1_CACHE_BYTES 64

#define ALIGN_PAGE      .align PAGE_SIZE
#define ALIGN_CACHE     .align L1_CACHE_BYTES

// Iterates from 'start' (inclusive) to 'end' (exclusive), invoking
// 'callback_macro' with the current loop index.
.macro COMPILE_TIME_FOR start, end, callback_macro
    .set __loop_idx, \start
    .rept (\end - \start)
        \callback_macro %__loop_idx
        .set __loop_idx, __loop_idx + 1
    .endr
.endm

#endif

// clang-format on

#endif