.section .text

.global flush_gdt
.type flush_gdt, @function

# =========================================================
# void flush_gdt(void* gdtr, uint16_t cs, uint16_t ss)
# ---------------------------------------------------------
# Arguments:
#   %rdi = Pointer to GDTR
#   %rsi = Code Segment Selector
#   %rdx = Data Segment Selector
# =========================================================
flush_gdt:
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
    pushq %rsi              # Push the new CS Selector
    leaq 1f(%rip), %rax     # Load the address of label `1`
    pushq %rax              # Push the return address (RIP)
    lretq                   # Pops RIP, then CS
1:
    retq

.global flush_tss
.type flush_tss, @function

# =========================================================
# void flush_tss(uint16_t tss_offset)
# ---------------------------------------------------------
# Arguments:
#   %rdi = TSS Selector Offset
# =========================================================
flush_tss:
    ltr %di
    ret