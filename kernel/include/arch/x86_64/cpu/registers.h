// Copyright 2016 The Fuchsia Authors
//
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT
// Original source (upto `#ifndef __ASSEMBLER__`):
// https://fuchsia.googlesource.com/fuchsia/+/refs/heads/main/zircon/kernel/arch/x86/include/arch/x86/registers.h

#ifndef KERNEL_CPU_REGISTERS_H
#define KERNEL_CPU_REGISTERS_H 1

// clang-format off

#define X86_IFRAME_OFFSET_RDI (0 * 8)
#define X86_IFRAME_OFFSET_RSI (1 * 8)
#define X86_IFRAME_OFFSET_RBP (2 * 8)
#define X86_IFRAME_OFFSET_RBX (3 * 8)
#define X86_IFRAME_OFFSET_RDX (4 * 8)
#define X86_IFRAME_OFFSET_RCX (5 * 8)
#define X86_IFRAME_OFFSET_RAX (6 * 8)
#define X86_IFRAME_OFFSET_R8  (7 * 8)
#define X86_IFRAME_OFFSET_R9  (8 * 8)
#define X86_IFRAME_OFFSET_R10 (9 * 8)
#define X86_IFRAME_OFFSET_R11 (10 * 8)
#define X86_IFRAME_OFFSET_R12 (11 * 8)
#define X86_IFRAME_OFFSET_R13 (12 * 8)
#define X86_IFRAME_OFFSET_R14 (13 * 8)
#define X86_IFRAME_OFFSET_R15 (14 * 8)

#define X86_IFRAME_OFFSET_VECTOR   (15 * 8)
#define X86_IFRAME_OFFSET_ERR_CODE (16 * 8)

#define X86_IFRAME_OFFSET_IP      (17 * 8)
#define X86_IFRAME_OFFSET_CS      (18 * 8)
#define X86_IFRAME_OFFSET_FLAGS   (19 * 8)
#define X86_IFRAME_OFFSET_USER_SP (20 * 8)
#define X86_IFRAME_OFFSET_USER_SS (21 * 8)

#define X86_IFRAME_SIZE (22 * 8)

// This header is intended to be included in both C and ASM
#define X86_CR0_PE               0x00000001ul  // protected mode enable
#define X86_CR0_MP               0x00000002ul  // monitor coprocessor
#define X86_CR0_EM               0x00000004ul  // emulation
#define X86_CR0_TS               0x00000008ul  // task switched
#define X86_CR0_ET               0x00000010ul  // extension type
#define X86_CR0_NE               0x00000020ul  // enable x87 exception
#define X86_CR0_WP               0x00010000ul  // supervisor write protect
#define X86_CR0_NW               0x20000000ul  // not write-through
#define X86_CR0_CD               0x40000000ul  // cache disable
#define X86_CR0_PG               0x80000000ul  // enable paging
#define X86_CR4_PAE              0x00000020ul  // PAE paging
#define X86_CR3_BASE_MASK        (((1ull << 39) - 1) << 12)
#define X86_CR4_PGE              0x00000080ul  // page global enable
#define X86_CR4_OSFXSR           0x00000200ul  // os supports fxsave
#define X86_CR4_OSXMMEXPT        0x00000400ul  // os supports xmm exception
#define X86_CR4_UMIP             0x00000800ul  // User-mode instruction prevention
#define X86_CR4_LA57             0x00001000ul  // 5-level paging
#define X86_CR4_VMXE             0x00002000ul  // enable vmx
#define X86_CR4_FSGSBASE         0x00010000ul  // enable {rd,wr}{fs,gs}base
#define X86_CR4_PCIDE            0x00020000ul  // Process-context ID enable
#define X86_CR4_OSXSAVE          0x00040000ul  // os supports xsave
#define X86_CR4_SMEP             0x00100000ul  // SMEP protection enabling
#define X86_CR4_SMAP             0x00200000ul  // SMAP protection enabling
#define X86_CR4_PKE              0x00400000ul  // Enable protection keys
#define X86_EFER_SCE             0x00000001ul  // enable SYSCALL
#define X86_EFER_LME             0x00000100ul  // long mode enable
#define X86_EFER_LMA             0x00000400ul  // long mode active
#define X86_EFER_NXE             0x00000800ul  // to enable execute disable bit
#define X86_MSR_IA32_PLATFORM_ID 0x00000017ul  // platform id
#define X86_MSR_IA32_APIC_BASE   0x0000001bul  // APIC base physical address
#define X86_MSR_IA32_TSC_ADJUST  0x0000003bul  // TSC adjust
#define X86_MSR_IA32_SPEC_CTRL   0x00000048ul  // Speculative Execution Controls
#define X86_SPEC_CTRL_IBRS       (1ull << 0)

// Partitions indirect branch predictors across hyperthreads
#define X86_SPEC_CTRL_STIBP            (1ull << 1)  // Single Thread Indirect Branch Predictors
#define X86_SPEC_CTRL_SSBD             (1ull << 2)
#define X86_MSR_SMI_COUNT              0x00000034   // Number of SMI interrupts since boot
#define X86_MSR_IA32_PRED_CMD          0x00000049   // Indirect Branch Prediction Command
#define X86_MSR_IA32_BIOS_UPDT_TRIG    0x00000079u  // Microcode Patch Loader
#define X86_MSR_IA32_BIOS_SIGN_ID      0x0000008b   // BIOS update signature
#define X86_MSR_IA32_MTRRCAP           0x000000fe   // MTRR capability
#define X86_MSR_IA32_ARCH_CAPABILITIES 0x0000010a
#define X86_ARCH_CAPABILITIES_RDCL_NO  (1ull << 0)
#define X86_ARCH_CAPABILITIES_IBRS_ALL (1ull << 1)
#define X86_ARCH_CAPABILITIES_RSBA     (1ull << 2)
#define X86_ARCH_CAPABILITIES_SSB_NO   (1ull << 4)
#define X86_ARCH_CAPABILITIES_MDS_NO   (1ull << 5)
#define X86_ARCH_CAPABILITIES_TSX_CTRL (1ull << 7)
#define X86_ARCH_CAPABILITIES_TAA_NO   (1ull << 8)
#define X86_MSR_IA32_FLUSH_CMD         0x0000010b   // L1D$ Flush control
#define X86_MSR_IA32_TSX_CTRL          0x00000122   // Control to enable/disable TSX instructions
#define X86_TSX_CTRL_RTM_DISABLE       (1ull << 0)  // Force all RTM instructions to abort
#define X86_TSX_CTRL_CPUID_DISABLE     (1ull << 1)  // Mask RTM and HLE in CPUID
#define X86_MSR_IA32_SYSENTER_CS       0x00000174   // SYSENTER CS
#define X86_MSR_IA32_SYSENTER_ESP      0x00000175   // SYSENTER ESP
#define X86_MSR_IA32_SYSENTER_EIP      0x00000176   // SYSENTER EIP
#define X86_MSR_IA32_MCG_CAP           0x00000179   // global machine check capability
#define X86_MSR_IA32_MCG_STATUS        0x0000017a   // global machine check status
#define X86_MSR_IA32_MISC_ENABLE       0x000001a0   // enable/disable misc processor features

#define X86_MSR_IA32_MISC_ENABLE_TURBO_DISABLE (1ull << 38)
#define X86_MSR_IA32_TEMPERATURE_TARGET        0x000001a2  // Temperature target
#define X86_MSR_IA32_ENERGY_PERF_BIAS          0x000001b0  // Energy / Performance Bias
#define X86_MSR_IA32_MTRR_PHYSBASE0            0x00000200  // MTRR PhysBase0
#define X86_MSR_IA32_MTRR_PHYSMASK0            0x00000201  // MTRR PhysMask0
#define X86_MSR_IA32_MTRR_PHYSMASK9            0x00000213  // MTRR PhysMask9
#define X86_MSR_IA32_MTRR_DEF_TYPE             0x000002ff  // MTRR default type
#define X86_MSR_IA32_MTRR_FIX64K_00000         0x00000250  // MTRR FIX64K_00000
#define X86_MSR_IA32_MTRR_FIX16K_80000         0x00000258  // MTRR FIX16K_80000
#define X86_MSR_IA32_MTRR_FIX16K_A0000         0x00000259  // MTRR FIX16K_A0000
#define X86_MSR_IA32_MTRR_FIX4K_C0000          0x00000268  // MTRR FIX4K_C0000
#define X86_MSR_IA32_MTRR_FIX4K_F8000          0x0000026f  // MTRR FIX4K_F8000
#define X86_MSR_IA32_PAT                       0x00000277  // PAT
#define X86_MSR_IA32_TSC_DEADLINE              0x000006e0  // TSC deadline
#define X86_MSR_IA32_X2APIC_APICID             0x00000802  // x2APIC ID Register (R/O)
#define X86_MSR_IA32_X2APIC_VERSION            0x00000803  // x2APIC Version Register (R/O)
#define X86_MSR_IA32_X2APIC_TPR                0x00000808  // x2APIC Task Priority Register (R/W)

#define X86_MSR_IA32_X2APIC_PPR  0x0000080A  // x2APIC Processor Priority Register (R/O)
#define X86_MSR_IA32_X2APIC_EOI  0x0000080B  // x2APIC EOI Register (W/O)
#define X86_MSR_IA32_X2APIC_LDR  0x0000080D  // x2APIC Logical Destination Register (R/O)
#define X86_MSR_IA32_X2APIC_SIVR 0x0000080F  // x2APIC Spurious Interrupt Vector Register (R/W)
#define X86_MSR_IA32_X2APIC_ISR0 0x00000810  // x2APIC In-Service Register Bits 31:0 (R/O)
#define X86_MSR_IA32_X2APIC_ISR1 0x00000811  // x2APIC In-Service Register Bits 63:32 (R/O)
#define X86_MSR_IA32_X2APIC_ISR2 0x00000812  // x2APIC In-Service Register Bits 95:64 (R/O)
#define X86_MSR_IA32_X2APIC_ISR3 0x00000813  // x2APIC In-Service Register Bits 127:96 (R/O)
#define X86_MSR_IA32_X2APIC_ISR4 0x00000814  // x2APIC In-Service Register Bits 159:128 (R/O)
#define X86_MSR_IA32_X2APIC_ISR5 0x00000815  // x2APIC In-Service Register Bits 191:160 (R/O)
#define X86_MSR_IA32_X2APIC_ISR6 0x00000816  // x2APIC In-Service Register Bits 223:192 (R/O)
#define X86_MSR_IA32_X2APIC_ISR7 0x00000817  // x2APIC In-Service Register Bits 255:224 (R/O)
#define X86_MSR_IA32_X2APIC_TMR0 0x00000818  // x2APIC Trigger Mode Register Bits 31:0 (R/O)
#define X86_MSR_IA32_X2APIC_TMR1 0x00000819  // x2APIC Trigger Mode Register Bits 63:32 (R/O)
#define X86_MSR_IA32_X2APIC_TMR2 0x0000081A  // x2APIC Trigger Mode Register Bits 95:64 (R/O)
#define X86_MSR_IA32_X2APIC_TMR3 0x0000081B  // x2APIC Trigger Mode Register Bits 127:96 (R/O)
#define X86_MSR_IA32_X2APIC_TMR4 0x0000081C  // x2APIC Trigger Mode Register Bits 159:128 (R/O)
#define X86_MSR_IA32_X2APIC_TMR5 0x0000081D  // x2APIC Trigger Mode Register Bits 191:160 (R/O)
#define X86_MSR_IA32_X2APIC_TMR6 0x0000081E  // x2APIC Trigger Mode Register Bits 223:192 (R/O)
#define X86_MSR_IA32_X2APIC_TMR7 0x0000081F  // x2APIC Trigger Mode Register Bits 255:224 (R/O)
#define X86_MSR_IA32_X2APIC_IRR0 0x00000820  // x2APIC Interrupt Request Register Bits 31:0 (R/O)
#define X86_MSR_IA32_X2APIC_IRR1 0x00000821  // x2APIC Interrupt Request Register Bits 63:32 (R/O)
#define X86_MSR_IA32_X2APIC_IRR2 0x00000822  // x2APIC Interrupt Request Register Bits 95:64 (R/O)
#define X86_MSR_IA32_X2APIC_IRR3 0x00000823  // x2APIC Interrupt Request Register Bits 127:96 (R/O)
#define X86_MSR_IA32_X2APIC_IRR4 0x00000824  // x2APIC Interrupt Request Register Bits 159:128 (R/O)
#define X86_MSR_IA32_X2APIC_IRR5 0x00000825  // x2APIC Interrupt Request Register Bits 191:160 (R/O)
#define X86_MSR_IA32_X2APIC_IRR6 0x00000826  // x2APIC Interrupt Request Register Bits 223:192 (R/O)
#define X86_MSR_IA32_X2APIC_IRR7 0x00000827  // x2APIC Interrupt Request Register Bits 255:224 (R/O)
#define X86_MSR_IA32_X2APIC_ESR  0x00000828  // x2APIC Error Status Register (R/W)

#define X86_MSR_IA32_X2APIC_LVT_CMCI    0x0000082F  // x2APIC LVT Corrected Machine Check Interrupt Register (R/W)
#define X86_MSR_IA32_X2APIC_ICR         0x00000830  // x2APIC Interrupt Command Register (R/W)
#define X86_MSR_IA32_X2APIC_LVT_TIMER   0x00000832  // x2APIC LVT Timer Interrupt Register (R/W)
#define X86_MSR_IA32_X2APIC_LVT_THERMAL 0x00000833  // x2APIC LVT Thermal Sensor Interrupt Register (R/W)
#define X86_MSR_IA32_X2APIC_LVT_PMI     0x00000834  // x2APIC LVT Performance Monitor Interrupt Register (R/W)

#define X86_MSR_IA32_X2APIC_LVT_LINT0  0x00000835  // x2APIC LVT LINT0 Register (R/W)
#define X86_MSR_IA32_X2APIC_LVT_LINT1  0x00000836  // x2APIC LVT LINT1 Register (R/W)
#define X86_MSR_IA32_X2APIC_LVT_ERROR  0x00000837  // x2APIC LVT Error Register (R/W)
#define X86_MSR_IA32_X2APIC_INIT_COUNT 0x00000838  // x2APIC Initial Count Register (R/W)
#define X86_MSR_IA32_X2APIC_CUR_COUNT  0x00000839  // x2APIC Current Count Register (R/O)
#define X86_MSR_IA32_X2APIC_DIV_CONF   0x0000083E  // x2APIC Divide Configuration Register (R/W)
#define X86_MSR_IA32_X2APIC_SELF_IPI   0x0000083F  // x2APIC Self IPI Register (W/O)
#define X86_MSR_IA32_EFER              0xc0000080  // EFER
#define X86_MSR_IA32_STAR              0xc0000081  // system call address
#define X86_MSR_IA32_LSTAR             0xc0000082  // long mode call address
#define X86_MSR_IA32_CSTAR             0xc0000083  // ia32-e compat call address
#define X86_MSR_IA32_FMASK             0xc0000084  // system call flag mask
#define X86_MSR_IA32_FS_BASE           0xc0000100  // fs base address
#define X86_MSR_IA32_GS_BASE           0xc0000101  // gs base address
#define X86_MSR_IA32_KERNEL_GS_BASE    0xc0000102  // kernel gs base
#define X86_MSR_IA32_TSC_AUX           0xc0000103  // TSC aux
#define X86_MSR_IA32_PM_ENABLE         0x00000770  // enable/disable HWP
#define X86_MSR_IA32_HWP_CAPABILITIES  0x00000771  // HWP performance range enumeration
#define X86_MSR_IA32_HWP_REQUEST       0x00000774  // power manage control hints
#define X86_MSR_AMD_VIRT_SPEC_CTRL     0xc001011f  // AMD speculative execution controls (See IA32_SPEC_CTRL)
#define X86_CR4_PSE                    0xffffffef  // Disabling PSE bit in the CR4

// Non-architectural MSRs
#define X86_MSR_POWER_CTL                       0x000001fc  // Power Control Register
#define X86_MSR_RAPL_POWER_UNIT                 0x00000606  // RAPL unit multipliers
#define X86_MSR_PKG_POWER_LIMIT                 0x00000610  // Package power limits
#define X86_MSR_PKG_ENERGY_STATUS               0x00000611  // Package energy status
#define X86_MSR_PKG_POWER_INFO                  0x00000614  // Package power range info
#define X86_MSR_DRAM_POWER_LIMIT                0x00000618  // DRAM RAPL power limit control
#define X86_MSR_DRAM_ENERGY_STATUS              0x00000619  // DRAM energy status
#define X86_MSR_PP0_POWER_LIMIT                 0x00000638  // PP0 RAPL power limit control
#define X86_MSR_PP0_ENERGY_STATUS               0x00000639  // PP0 energy status
#define X86_MSR_PP1_POWER_LIMIT                 0x00000640  // PP1 RAPL power limit control
#define X86_MSR_PP1_ENERGY_STATUS               0x00000641  // PP1 energy status
#define X86_MSR_PLATFORM_ENERGY_COUNTER         0x0000064d  // Platform energy counter
#define X86_MSR_PPERF                           0x0000064e  // Productive performance count
#define X86_MSR_PERF_LIMIT_REASONS              0x0000064f  // Clipping cause register
#define X86_MSR_GFX_PERF_LIMIT_REASONS          0x000006b0  // Clipping cause register for graphics
#define X86_MSR_PLATFORM_POWER_LIMIT            0x0000065c  // Platform power limit control
#define X86_MSR_AMD_F10_DE_CFG                  0xc0011029  // AMD Family 10h+ decode config
#define X86_MSR_AMD_F10_DE_CFG_LFENCE_SERIALIZE (1 << 1)
#define X86_MSR_AMD_LS_CFG                      0xc0011020  // Load/store unit configuration
#define X86_AMD_LS_CFG_F15H_SSBD                (1ull << 54)
#define X86_AMD_LS_CFG_F16H_SSBD                (1ull << 33)
#define X86_AMD_LS_CFG_F17H_SSBD                (1ull << 10)
#define X86_MSR_K7_HWCR                         0xc0010015    // AMD Hardware Configuration
#define X86_MSR_K7_HWCR_CPB_DISABLE             (1ull << 25)  // Set to disable turbo ('boost')

// KVM MSRs
#define X86_MSR_KVM_PV_EOI_EN        0x4b564d04  // Enable paravirtual fast APIC EOI
#define X86_MSR_KVM_PV_EOI_EN_ENABLE (1ull << 0)

// EFLAGS/RFLAGS
#define X86_FLAGS_CF            (1 << 0)
#define X86_FLAGS_PF            (1 << 2)
#define X86_FLAGS_AF            (1 << 4)
#define X86_FLAGS_ZF            (1 << 6)
#define X86_FLAGS_SF            (1 << 7)
#define X86_FLAGS_TF            (1 << 8)
#define X86_FLAGS_IF            (1 << 9)
#define X86_FLAGS_DF            (1 << 10)
#define X86_FLAGS_OF            (1 << 11)
#define X86_FLAGS_STATUS_MASK   (0xfff)
#define X86_FLAGS_IOPL_MASK     (3 << 12)
#define X86_FLAGS_IOPL_SHIFT    (12)
#define X86_FLAGS_NT            (1 << 14)
#define X86_FLAGS_RF            (1 << 16)
#define X86_FLAGS_VM            (1 << 17)
#define X86_FLAGS_AC            (1 << 18)
#define X86_FLAGS_VIF           (1 << 19)
#define X86_FLAGS_VIP           (1 << 20)
#define X86_FLAGS_ID            (1 << 21)
#define X86_FLAGS_RESERVED_ONES 0x2
#define X86_FLAGS_RESERVED      0xffc0802a
#define X86_FLAGS_USER                                                                         \
    (X86_FLAGS_CF | X86_FLAGS_PF | X86_FLAGS_AF | X86_FLAGS_ZF | X86_FLAGS_SF | X86_FLAGS_TF | \
     X86_FLAGS_DF | X86_FLAGS_OF | X86_FLAGS_NT | X86_FLAGS_AC | X86_FLAGS_ID)

// DR6
#define X86_DR6_B0 (1ul << 0)
#define X86_DR6_B1 (1ul << 1)
#define X86_DR6_B2 (1ul << 2)
#define X86_DR6_B3 (1ul << 3)
#define X86_DR6_BD (1ul << 13)
#define X86_DR6_BS (1ul << 14)
#define X86_DR6_BT (1ul << 15)

#define X86_DR6_USER_MASK (X86_DR6_B0 | X86_DR6_B1 | X86_DR6_B2 | X86_DR6_B3 | X86_DR6_BD | X86_DR6_BS | X86_DR6_BT)
#define X86_DR6_MASK (0xffff0ff0ul)

// DR7
#define X86_DR7_L0   (1ul << 0)
#define X86_DR7_G0   (1ul << 1)
#define X86_DR7_L1   (1ul << 2)
#define X86_DR7_G1   (1ul << 3)
#define X86_DR7_L2   (1ul << 4)
#define X86_DR7_G2   (1ul << 5)
#define X86_DR7_L3   (1ul << 6)
#define X86_DR7_G3   (1ul << 7)
#define X86_DR7_LE   (1ul << 8)
#define X86_DR7_GE   (1ul << 9)
#define X86_DR7_GD   (1ul << 13)
#define X86_DR7_RW0  (3ul << 16)
#define X86_DR7_LEN0 (3ul << 18)
#define X86_DR7_RW1  (3ul << 20)
#define X86_DR7_LEN1 (3ul << 22)
#define X86_DR7_RW2  (3ul << 24)
#define X86_DR7_LEN2 (3ul << 26)
#define X86_DR7_RW3  (3ul << 28)
#define X86_DR7_LEN3 (3ul << 30)

#define X86_DR7_USER_MASK                                                                       \
    (X86_DR7_L0 | X86_DR7_G0 | X86_DR7_L1 | X86_DR7_G1 | X86_DR7_L2 | X86_DR7_G2 | X86_DR7_L3 | \
     X86_DR7_G3 | X86_DR7_RW0 | X86_DR7_LEN0 | X86_DR7_RW1 | X86_DR7_LEN1 | X86_DR7_RW2 |       \
     X86_DR7_LEN2 | X86_DR7_RW3 | X86_DR7_LEN3)

#define X86_XCR0_X87       0x00000001  // x87 FPU/MMX State
#define X86_XCR0_SSE       0x00000002  // SSE State (XMM registers)
#define X86_XCR0_AVX       0x00000004  // AVX State (YMM_Hi128)
#define X86_XCR0_BNDREG    0x00000008  // MPX Bound Registers (BND0-BND3)
#define X86_XCR0_BNDCSR    0x00000010  // MPX Bound Config/Status (BNDCFGU/S)
#define X86_XCR0_OPMASK    0x00000020  // AVX-512 Opmask (k0-k7)
#define X86_XCR0_ZMM_Hi256 0x00000040  // AVX-512 Upper 256 bits (ZMM0-15)
#define X86_XCR0_Hi_ZMM    0x00000080  // AVX-512 Upper 16 regs (ZMM16-31)
#define X86_XCR0_PT        0x00000100  // Processor Trace State
#define X86_XCR0_PKRU      0x00000200  // Protection Key Rights (PKRU)
#define X86_XCR0_PASID     0x00000400  // Process Address Space ID
#define X86_XCR0_CET_U     0x00000800  // Control-flow Enforcement (User)
#define X86_XCR0_CET_S     0x00001000  // Control-flow Enforcement (Supervisor)
#define X86_XCR0_HDC       0x00002000  // Hardware Duty Cycling State
#define X86_XCR0_UINTR     0x00004000  // User Interrupts State
#define X86_XCR0_LBR       0x00008000  // Last Branch Record State
#define X86_XCR0_HWP       0x00010000  // Hardware P-States
#define X86_XCR0_XTILECFG  0x00020000  // AMX Tile Configuration
#define X86_XCR0_XTILEDATA 0x00040000  // AMX Tile Data
#define X86_XCR0_APX       0x00080000  // Advanced Performance Extensions

// MXCSR
#define X86_MXCSR_IE         0x00001  // Invalid Operation Flag
#define X86_MXCSR_DE         0x00002  // Denormal Flag
#define X86_MXCSR_ZE         0x00004  // Divide-by-Zero Flag
#define X86_MXCSR_OE         0x00008  // Overflow Flag
#define X86_MXCSR_UE         0x00010  // Underflow Flag
#define X86_MXCSR_PE         0x00020  // Precision Flag
#define X86_MXCSR_DAZ        0x00040  // Denormals Are Zeros
#define X86_MXCSR_IM         0x00080  // Invalid Operation Mask
#define X86_MXCSR_DM         0x00100  // Denormal Mask
#define X86_MXCSR_ZM         0x00200  // Divide-by-Zero Mask
#define X86_MXCSR_OM         0x00400  // Overflow Mask
#define X86_MXCSR_UM         0x00800  // Underflow Mask
#define X86_MXCSR_PM         0x01000  // Precision Mask
#define X86_MXCSR_RC_MASK    0x06000  // Rounding Control Mask
#define X86_MXCSR_RC_NEAREST 0x00000  // Round to Nearest (Even)
#define X86_MXCSR_RC_DOWN    0x02000  // Round Down (toward -Inf)
#define X86_MXCSR_RC_UP      0x04000  // Round Up (toward +Inf)
#define X86_MXCSR_RC_TRUNC   0x06000  // Round toward Zero (Truncate)
#define X86_MXCSR_FTZ        0x08000  // Flush to Zero

// INVPCID Types
#define INVPCID_INDIVIDUAL_ADDR           0  // Invalidate specific addr in specific PCID
#define INVPCID_SINGLE_CONTEXT            1  // Invalidate all entries for specific PCID
#define INVPCID_ALL_CONTEXT               2  // Invalidate all entries for all PCIDs (including Global)
#define INVPCID_ALL_CONTEXT_RETAIN_GLOBAL 3  // Invalidate all entries for all PCIDs (excluding Global)

// Basic Leaves
#define CPUID_VENDOR_INFO               0x00
#define CPUID_FEATURE_INFO              0x01
#define CPUID_CACHE_TLB_DESCRIPTORS     0x02
#define CPUID_DETERMINISTIC_CACHE       0x04
#define CPUID_MONITOR_MWAIT             0x05
#define CPUID_THERMAL_POWER_MGMT        0x06
#define CPUID_EXTENDED_FEATURES         0x07
#define CPUID_ARCH_PERF_MON             0x0a
#define CPUID_EXTENDED_TOPOLOGY         0x0b
#define CPUID_XSAVE_FEATURES            0x0d
#define CPUID_RDT_MONITORING            0x0f
#define CPUID_RDT_ALLOCATION            0x10
#define CPUID_HYBRID_INFO               0x1a // For Alder/Raptor Lake

// Primary Topology Leaf
#define CPUID_V2_EXTENDED_TOPOLOGY    0x1f

// Level Types returned in ECX[15:8]
#define CPUID_TOPOLOGY_LEVEL_INVALID  0x00
#define CPUID_TOPOLOGY_LEVEL_SMT      0x01
#define CPUID_TOPOLOGY_LEVEL_CORE     0x02
#define CPUID_TOPOLOGY_LEVEL_MODULE   0x03
#define CPUID_TOPOLOGY_LEVEL_TILE     0x04
#define CPUID_TOPOLOGY_LEVEL_DIE      0x05

// Extended Leaves
#define CPUID_EXT_MAX_FUNCTION          0x80000000
#define CPUID_EXT_FEATURE_INFO          0x80000001
#define CPUID_BRAND_STRING_1            0x80000002
#define CPUID_BRAND_STRING_2            0x80000003
#define CPUID_BRAND_STRING_3            0x80000004
#define CPUID_EXT_L2_CACHE_INFO         0x80000006
#define CPUID_EXT_ADDR_SIZE             0x80000008

// clang-format on

#ifndef __ASSEMBLER__
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define DEFINE_CR_ACCESSOR(n)                                    \
    static inline uint64_t read_cr##n(void) {                    \
        uint64_t val;                                            \
        asm volatile("mov %%cr" #n ", %0" : "=r"(val));          \
        return val;                                              \
    }                                                            \
                                                                 \
    static inline void write_cr##n(uint64_t val) {               \
        asm volatile("mov %0, %%cr" #n : : "r"(val) : "memory"); \
    }

#define DEFINE_DR_ACCESSOR(n)                                    \
    static inline uint64_t read_dr##n(void) {                    \
        uint64_t val;                                            \
        asm volatile("mov %%dr" #n ", %0" : "=r"(val));          \
        return val;                                              \
    }                                                            \
                                                                 \
    static inline void write_dr##n(uint64_t val) {               \
        asm volatile("mov %0, %%dr" #n : : "r"(val) : "memory"); \
    }

static inline uint64_t read_msr(uint64_t address) {
    uint32_t low, high;
    asm volatile("rdmsr" : "=a"(low), "=d"(high) : "c"(address));
    return ((uint64_t)high << 32) | low;
}

static inline void write_msr(uint64_t address, uint64_t value) {
    uint32_t low  = value & 0xffffffff;
    uint32_t high = value >> 32;

    asm volatile("wrmsr" ::"a"(low), "d"(high), "c"(address));
}

static inline void invlpg(const void* addr) {
    asm volatile("invlpg (%0)" : : "r"(addr) : "memory");
}

// The descriptor required by the INVPCID instruction (128 bits)
typedef struct [[gnu::packed]] {
    uint64_t pcid : 12;  // Low 12 bits: PCID
    uint64_t rsvd : 52;  // Reserved (must be 0)
    uint64_t addr;       // Linear Address (only used for type 0)
} invpcid_desc_t;

static inline void invpcid(unsigned long type, uint64_t pcid, uint64_t addr) {
    invpcid_desc_t desc = {0};
    desc.pcid           = pcid;
    desc.addr           = addr;

    asm volatile("invpcid %0, %1" : : "m"(desc), "r"(type) : "memory");
}

DEFINE_CR_ACCESSOR(0)
DEFINE_CR_ACCESSOR(2)
DEFINE_CR_ACCESSOR(3)
DEFINE_CR_ACCESSOR(4)

// Define accessors for the Breakpoint Address Registers
DEFINE_DR_ACCESSOR(0)
DEFINE_DR_ACCESSOR(1)
DEFINE_DR_ACCESSOR(2)
DEFINE_DR_ACCESSOR(3)

// Define accessors for Status (DR6) and Control (DR7)
DEFINE_DR_ACCESSOR(6)
DEFINE_DR_ACCESSOR(7)

static inline uint32_t read_mxcsr(void) {
    uint32_t mxcsr = 0;
    asm volatile("stmxcsr %0" : "=m"(mxcsr));
    return mxcsr;
}

static inline void write_mxcsr(uint32_t mxcsr) {
    asm volatile("ldmxcsr %0" ::"m"(mxcsr));
}

#define XCR_XFEATURE_ENABLED_MASK 0

static inline uint64_t read_xcr0(void) {
    uint32_t low  = 0;
    uint32_t high = 0;
    asm volatile("xgetbv" : "=a"(low), "=d"(high) : "c"(XCR_XFEATURE_ENABLED_MASK));
    return ((uint64_t)high << 32) | low;
}

static inline void write_xcr0(uint64_t xcr0) {
    uint32_t low  = xcr0 & 0xFFFFFFFF;
    uint32_t high = xcr0 >> 32;

    asm volatile("xsetbv" : : "a"(low), "d"(high), "c"(XCR_XFEATURE_ENABLED_MASK) : "memory");
}

#ifdef __cplusplus
}
#endif

#endif
#endif