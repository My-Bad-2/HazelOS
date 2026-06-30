#include "asm.h"

.section .text.fred_entry, "ax"
ALIGN_PAGE

SYM_DATA(fred_entry_page)
EXTERN_FUNC(fred_dispatch)

SYM_FUNC_START(fred_ring3_entry)
  swapgs
  PUSHA_64_MOVQ

  mov %rsp, %rdi
  cld
  call fred_dispatch

  POPA_64_MOVQ
  swapgs
  eretu
SYM_FUNC_END(fred_ring3_entry)

// FRED requires the ring0 entry function to be at 256-byte offset from Ring3 entry base
.balign 0x100
SYM_FUNC_START(fred_ring0_entry)
  PUSHA_64_MOVQ

  mov %rsp, %rdi
  cld
  call fred_dispatch

  POPA_64_MOVQ
  erets
SYM_FUNC_END(fred_ring0_entry)