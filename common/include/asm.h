#ifndef KERNEL_ASM_H
#define KERNEL_ASM_H 1

#include "arch_asm.h"

// clang-format off

#ifdef __ASSEMBLER__

#define ALIGN_PAGE  .balign PAGE_SIZE
#define ALIGN_CACHE .balign L1_CACHE_BYTES
#define ALIGN_FUNC  .balign 16 ASM_ALIGN_FILL


#define SYM_FUNC_START(name) \
  ALIGN_FUNC;                \
  .global name;              \
  .type name, @function;     \
name:                        \
  .cfi_startproc

#define SYM_FUNC_END(name) \
  .cfi_endproc;            \
  .size name, .- name

#define SYM_FUNC_START_LOCAL(name) \
  ALIGN_FUNC;                      \
  .type name, @function;           \
name:                              \
  .cfi_startproc

#define SYM_FUNC_START_WEAK(name) \
  ALIGN_FUNC;                     \
  .weak name;                     \
  .type name, @function;          \
name:                             \
  .cfi_startproc

/* Moves symbol to unlikely execution path sections */
#define SYM_FUNC_START_COLD(name)   \
  .pushsection.text.unlikely, "ax"; \
  ALIGN_FUNC;                       \
  .global name;                     \
  .type name, @function;            \
name:                               \
  .cfi_startproc

#define SYM_FUNC_END_COLD(name) \
  SYM_FUNC_END(name);           \
  .popsection

#define SYM_DATA(name) \
  .global name;        \
  .type name, @object; \
name:

#define EXTERN_FUNC(x) .extern x

/**
 * Iterates from [start, end), invoking 'callback_macro' with the current loop index.
 */
.macro COMPILE_TIME_FOR start, end, callback_macro
    .set __loop_idx, \start
    .rept (\end - \start)
        \callback_macro %__loop_idx
        .set __loop_idx, __loop_idx + 1
    .endr
.endm

#endif  // __ASSEMBLER__

// clang-format on

#endif  // KERNEL_ASM_H