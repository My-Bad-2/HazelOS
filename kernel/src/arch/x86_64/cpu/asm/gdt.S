#include <asm.h>

.section .text

# =========================================================
# void flush_gdt(void* gdtr, uint16_t cs, uint16_t ss)
# ---------------------------------------------------------
# Arguments:
#   %rdi = Pointer to GDTR
#   %rsi = Code Segment Selector
#   %rdx = Data Segment Selector
# =========================================================
SYM_FUNC_START(flush_gdt)
    lgdtq (%rdi)

    # Reload Data Segment
    movw %dx, %ax
    movw %ax, %ds
    movw %ax, %es
    movw %ax, %ss

    # Clear FS and GS
    xorw %ax, %ax
    movw %ax, %fs
    movw %ax, %gs

    # Reload Code Segment
    push_reg %rsi           # Push the new CS Selector
    leaq 1f(%rip), %rax     # Load the address of label `1`
    push_reg %rax           # Push the return address (RIP)
    lretq                   # Pops RIP, then CS
1:
    RET_AND_SPECULATION_POSTFENCE
SYM_FUNC_END(flush_gdt)

# =========================================================
# void flush_tss(uint16_t tss_offset)
# ---------------------------------------------------------
# Arguments:
#   %rdi = TSS Selector Offset
# =========================================================
SYM_FUNC_START(flush_tss)
    ltr %di
    RET_AND_SPECULATION_POSTFENCE
SYM_FUNC_END(flush_tss)