#ifndef KERNEL_ARCH_AARCH64_ASM_H
#define KERNEL_ARCH_AARCH64_ASM_H 1

// clang-format off

#if defined(__ASSEMBLER__) && defined(__aarch64__)

#define L1_CACHE_BYTES 64
#define PAGE_SIZE      4096
/* NOP (0xd503201f) */
#define ASM_ALIGN_FILL 0xd503201f

#define SMP_MB()  dmb ish
#define SMP_RMB() dmb ishld
#define SMP_WMB() dmb ishst

.macro push_pair reg1, reg2
  stp \reg1, \reg2, [sp, #-16]!
  .cfi_adjust_cfa_offset 16
  .cfi_rel_offset \reg1, 0
  .cfi_rel_offset \reg2, 8
.endm

.macro pop_pair reg1, reg2
  ldp \reg1, \reg2, [sp], #16
  .cfi_adjust_cfa_offset -16
  .cfi_restore \reg1
  .cfi_restore \reg2
.endm

.macro FRAME_BEGIN
#if CONFIG_FRAME_POINTER
  push_pair x29, x30
  mov x29, sp
  .cfi_def_cfa_register x29
#endif
.endm

.macro FRAME_END
#if CONFIG_FRAME_POINTER
  pop_pair x29, x30
  .cfi_def_cfa sp, 0
#endif
.endm

#define RET_AND_SPECULATION_POSTFENCE   ret; sb
#define JMP_AND_SPECULATION_POSTFENCE(x) b x; sb

#endif // defined(__ASSEMBLER__) && defined(__aarch64__)

// clang-format on

#endif // KERNEL_ARCH_AARCH64_ASM_H
