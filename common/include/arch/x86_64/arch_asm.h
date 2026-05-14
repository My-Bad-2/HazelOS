#ifndef KERNEL_ARCH_X86_64_ASM_H
#define KERNEL_ARCH_X86_64_ASM_H 1

// clang-format off

#if defined(__ASSEMBLER__) && defined(__x86_64__)

#define L1_CACHE_BYTES 64
#define PAGE_SIZE      4096
/* NOP (0x90) */
#define ASM_ALIGN_FILL , 0x90

#define LOCK_PREFIX lock;

.macro ATOMIC_ADD ptr_reg, val_reg
  LOCK_PREFIX
  addq \val_reg, (\ptr_reg)
.endm

.macro ATOMIC_DEC ptr_reg
  LOCK_PREFIX
  decq (\ptr_reg)
.endm

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

.macro HW_MEMSET dest_reg, val_reg, count_reg
  movq \dest_reg, %rdi
  movq \val_reg, %rax
  movq \count_reg, %rcx
  rep stosb
.endm

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
  .cfi_adjust_cfa_offset -8
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
  push_reg %rax; push_reg %rbx; push_reg %rcx; push_reg %rdx
  push_reg %rsi; push_reg %rdi; push_reg %rbp; push_reg %r8
  push_reg %r9;  push_reg %r10; push_reg %r11; push_reg %r12
  push_reg %r13; push_reg %r14; push_reg %r15
.endm

.macro POPA_64
  pop_reg %r15; pop_reg %r14; pop_reg %r13; pop_reg %r12
  pop_reg %r11; pop_reg %r10; pop_reg %r9;  pop_reg %r8
  pop_reg %rbp; pop_reg %rdi; pop_reg %rsi; pop_reg %rdx
  pop_reg %rcx; pop_reg %rbx; pop_reg %rax
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

/* Memory Barriers */
#define SMP_MB()  mfence
#define SMP_RMB() lfence
#define SMP_WMB() sfence

/* Speculation Mitigation */
#define RET_AND_SPECULATION_POSTFENCE   ret; int3
#define JMP_AND_SPECULATION_POSTFENCE(x) jmp x; int3

.macro CALL_NOSPEC reg
  call    999f
  int3
999:
  movq    \reg, (%rsp)
  RET_AND_SPECULATION_POSTFENCE
.endm

.macro JMP_NOSPEC reg
  call    999f
  int3
999:
  movq    \reg, (%rsp)
  RET_AND_SPECULATION_POSTFENCE
.endm

#endif // defined(__ASSEMBLER__) && defined(__x86_64__)

// clang-format on

#endif  // KERNEL_ARCH_X86_64_ASM_H