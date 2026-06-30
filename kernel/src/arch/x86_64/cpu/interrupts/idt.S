#include "asm.h"

/**
  Offset of data pushed by hardware (before Vector/Error is pushed)
  SS - 32 bytes
  RSP - 24 bytes
  RFLAGS - 16 bytes
  CS - 8 bytes
  RIP - 0 bytes
*/

.section .text.idt_entry, "ax"
ALIGN_FUNC
EXTERN_FUNC(idt_dispatch)
SYM_FUNC_START_LOCAL(idt_common_stub)
  // Hardware pushes (40 bytes) + Vector/Error (16 bytes) = 56 bytes
  .cfi_def_cfa_offset 56

  PUSHA_64_MOVQ

  // CS is at [rsp + 120 (GPRs) + 16 (Vec + Error) + 8 (RIP)] = 144
  testb $3, 144(%rsp)
  jz .L_from_kernel

  swapgs
  lfence // Spectre v1 Mitigation

.L_from_kernel:
  movq %rsp, %rdi
  cld
  call idt_dispatch

  testb $3, 144(%rsp)
  jz .L_return_from_kernel
  
  swapgs

.L_return_from_kernel:
  POPA_64_MOVQ

  // Clean up Vector + Error code
  add_to_sp 16

  iretq
SYM_FUNC_END(idt_common_stub)

#define MSR_GS_BASE 0xC0000101

// special entry for NMIs
SYM_FUNC_START(idt_stub_2)
  .cfi_def_cfa_offset 40

  push_value $0                 
  push_value $2                 

  PUSHA_64_MOVQ

  ALT_BEGIN
    READ_MSR MSR_GS_BASE
    testl %edx, %edx
  ALT_REPL 64
    rdgsbaseq %rax
    testq %rax, %rax
  ALT_END

  // If the sign bit of EDX is set, we are in Kernel GS.
  js .L_nmi_kernel_gs

  // If GS is positive, we interrupted user space
  swapgs
  lfence

  movq %rsp, %rdi
  cld
  call idt_dispatch

  swapgs
  jmp .L_nmi_return

.L_nmi_kernel_gs:
  movq %rsp, %rdi
  cld
  call idt_dispatch

.L_nmi_return:
  POPA_64_MOVQ
  add_to_sp 16
  iretq
SYM_FUNC_END(idt_stub_2)

.macro IDT_STUB vector, has_error
SYM_FUNC_START(idt_stub_\vector)
  .cfi_def_cfa_offset 40

  .if \has_error == 0
    push_value $0
  .endif

  push_value $\vector
  jmp idt_common_stub
SYM_FUNC_END(idt_stub_\vector)
.endm

IDT_STUB 0, 0
IDT_STUB 1, 0
IDT_STUB 3,  0   
IDT_STUB 4,  0   
IDT_STUB 5,  0   
IDT_STUB 6,  0   
IDT_STUB 7,  0   
IDT_STUB 8,  1   // Double Fault (Has Error)
IDT_STUB 9,  0   
IDT_STUB 10, 1   // Invalid TSS (Has Error)
IDT_STUB 11, 1   // Segment Not Present (Has Error)
IDT_STUB 12, 1   // Stack Segment Fault (Has Error)
IDT_STUB 13, 1   // General Protection Fault (Has Error)
IDT_STUB 14, 1   // Page Fault (Has Error)
IDT_STUB 15, 0   
IDT_STUB 16, 0   
IDT_STUB 17, 1   // Alignment Check (Has Error)
IDT_STUB 18, 0   // Machine Check
IDT_STUB 19, 0   
IDT_STUB 20, 0   
IDT_STUB 21, 1   // Control Protection (Has Error)

.altmacro

_vector = 22
.rept 256 - 22
  IDT_STUB %_vector, 0
  _vector = _vector + 1
.endr

.macro MAKE_ISR_POINTER vector
  .quad idt_stub_\vector
.endm

.section .data
.balign 8
SYM_DATA(isr_stub_table)
  _vector_ptr = 0
  .rept 256
    MAKE_ISR_POINTER %_vector_ptr
    _vector_ptr = _vector_ptr + 1
  .endr

.noaltmacro