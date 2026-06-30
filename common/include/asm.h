#ifndef COMMON_ASM_H
#define COMMON_ASM_H 1

// clang-format off

#ifdef __ASSEMBLER__

#include "arch_asm.h"

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

#define SYM_DATA_LOCAL(name) \
  .type name, @object;       \
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

// // USAGE: ALTERNATIVE "default_code", "optimized_code", feature_id
// .macro ALTERNATIVE oldinstr, newinstr, feature
// .L_alt_old_\@:
//     \oldinstr
// .L_alt_old_end_\@:

// .pushsection .altinstructions, "a"
//     .balign 4
//     .long .L_alt_old_\@ - .
//     .long .L_alt_new_\@ - .
//     .short \feature
//     .byte .L_alt_old_end_\@ - .L_alt_old_\@
//     .byte .L_alt_new_end_\@ - .L_alt_new_\@
// .popsection

// .pushsection .init.altinstr_replacement, "ax", @progbits
// .L_alt_new_\@:
//     \newinstr
// .L_alt_new_end_\@:
// .popsection

// .pushsection .discard.alt_size_checks, "aw", @progbits
//     /* If the replacement is larger, this evaluates to a negative number.
//        The assembler will throw a terminal error for negative .space allocation. */
//     .space (.L_alt_old_end_\@ - .L_alt_old_\@) - (.L_alt_new_end_\@ - .L_alt_new_\@)
// .popsection

// .endm

.macro ALT_BEGIN
661:
.endm

.macro ALT_REPL feature
662:
    .pushsection .altinstructions, "a"
        .balign 4
        .long 661b - .            // 32-bit relative offset to original code
        .long 663f - .            // 32-bit relative offset to replacement code
        .short \feature           // CPU Feature Flag ID
        .byte 662b - 661b         // Size of original code
        .byte 664f - 663f         // Size of replacement code
    .popsection

    .pushsection .init.altinstr_replacement, "ax", @progbits
663:
.endm

.macro ALT_END
664:
    .popsection

    // Compile-time safety check: ensures replacement code isn't larger than original
    .pushsection .discard.alt_size_checks, "aw", @progbits
        .space (662b - 661b) - (664b - 663b)
    .popsection
.endm

#endif  // __ASSEMBLER__

// clang-format on

#endif  // KERNEL_ASM_H