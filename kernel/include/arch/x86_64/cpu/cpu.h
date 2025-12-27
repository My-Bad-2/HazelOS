#ifndef KERNEL_CPU_H
#define KERNEL_CPU_H 1

#include <stdint.h>

#define FEATURE_FPU          (struct cpu_features){.leaf = FEATURE_LEAF1, .reg = 3, .bit = 0}
#define FEATURE_VME          (struct cpu_features){.leaf = FEATURE_LEAF1, .reg = 3, .bit = 1}
#define FEATURE_DE           (struct cpu_features){.leaf = FEATURE_LEAF1, .reg = 3, .bit = 2}
#define FEATURE_PSE          (struct cpu_features){.leaf = FEATURE_LEAF1, .reg = 3, .bit = 3}
#define FEATURE_TSC          (struct cpu_features){.leaf = FEATURE_LEAF1, .reg = 3, .bit = 4}
#define FEATURE_MSR          (struct cpu_features){.leaf = FEATURE_LEAF1, .reg = 3, .bit = 5}
#define FEATURE_PAE          (struct cpu_features){.leaf = FEATURE_LEAF1, .reg = 3, .bit = 6}
#define FEATURE_MCE          (struct cpu_features){.leaf = FEATURE_LEAF1, .reg = 3, .bit = 7}
#define FEATURE_CX8          (struct cpu_features){.leaf = FEATURE_LEAF1, .reg = 3, .bit = 8}
#define FEATURE_APIC         (struct cpu_features){.leaf = FEATURE_LEAF1, .reg = 3, .bit = 9}
#define FEATURE_SEP          (struct cpu_features){.leaf = FEATURE_LEAF1, .reg = 3, .bit = 11}
#define FEATURE_MTRR         (struct cpu_features){.leaf = FEATURE_LEAF1, .reg = 3, .bit = 12}
#define FEATURE_PGE          (struct cpu_features){.leaf = FEATURE_LEAF1, .reg = 3, .bit = 13}
#define FEATURE_MCA          (struct cpu_features){.leaf = FEATURE_LEAF1, .reg = 3, .bit = 14}
#define FEATURE_CMOV         (struct cpu_features){.leaf = FEATURE_LEAF1, .reg = 3, .bit = 15}
#define FEATURE_PAT          (struct cpu_features){.leaf = FEATURE_LEAF1, .reg = 3, .bit = 16}
#define FEATURE_PSE36        (struct cpu_features){.leaf = FEATURE_LEAF1, .reg = 3, .bit = 17}
#define FEATURE_PSN          (struct cpu_features){.leaf = FEATURE_LEAF1, .reg = 3, .bit = 18}
#define FEATURE_CLFSH        (struct cpu_features){.leaf = FEATURE_LEAF1, .reg = 3, .bit = 19}
#define FEATURE_DS           (struct cpu_features){.leaf = FEATURE_LEAF1, .reg = 3, .bit = 21}
#define FEATURE_ACPI         (struct cpu_features){.leaf = FEATURE_LEAF1, .reg = 3, .bit = 22}
#define FEATURE_MMX          (struct cpu_features){.leaf = FEATURE_LEAF1, .reg = 3, .bit = 23}
#define FEATURE_FXSR         (struct cpu_features){.leaf = FEATURE_LEAF1, .reg = 3, .bit = 24}
#define FEATURE_SSE          (struct cpu_features){.leaf = FEATURE_LEAF1, .reg = 3, .bit = 25}
#define FEATURE_SSE2         (struct cpu_features){.leaf = FEATURE_LEAF1, .reg = 3, .bit = 26}
#define FEATURE_SS           (struct cpu_features){.leaf = FEATURE_LEAF1, .reg = 3, .bit = 27}
#define FEATURE_HTT          (struct cpu_features){.leaf = FEATURE_LEAF1, .reg = 3, .bit = 28}
#define FEATURE_TM           (struct cpu_features){.leaf = FEATURE_LEAF1, .reg = 3, .bit = 29}
#define FEATURE_PBE          (struct cpu_features){.leaf = FEATURE_LEAF1, .reg = 3, .bit = 31}
#define FEATURE_SSE3         (struct cpu_features){.leaf = FEATURE_LEAF1, .reg = 2, .bit = 0}
#define FEATURE_PCLMULQDQ    (struct cpu_features){.leaf = FEATURE_LEAF1, .reg = 2, .bit = 1}
#define FEATURE_DTES64       (struct cpu_features){.leaf = FEATURE_LEAF1, .reg = 2, .bit = 2}
#define FEATURE_MONITOR      (struct cpu_features){.leaf = FEATURE_LEAF1, .reg = 2, .bit = 3}
#define FEATURE_DS_CPL       (struct cpu_features){.leaf = FEATURE_LEAF1, .reg = 2, .bit = 4}
#define FEATURE_VMX          (struct cpu_features){.leaf = FEATURE_LEAF1, .reg = 2, .bit = 5}
#define FEATURE_SMX          (struct cpu_features){.leaf = FEATURE_LEAF1, .reg = 2, .bit = 6}
#define FEATURE_EST          (struct cpu_features){.leaf = FEATURE_LEAF1, .reg = 2, .bit = 7}
#define FEATURE_TM2          (struct cpu_features){.leaf = FEATURE_LEAF1, .reg = 2, .bit = 8}
#define FEATURE_SSSE3        (struct cpu_features){.leaf = FEATURE_LEAF1, .reg = 2, .bit = 9}
#define FEATURE_CNXT_ID      (struct cpu_features){.leaf = FEATURE_LEAF1, .reg = 2, .bit = 10}
#define FEATURE_SDBG         (struct cpu_features){.leaf = FEATURE_LEAF1, .reg = 2, .bit = 11}
#define FEATURE_FMA          (struct cpu_features){.leaf = FEATURE_LEAF1, .reg = 2, .bit = 12}
#define FEATURE_CX16         (struct cpu_features){.leaf = FEATURE_LEAF1, .reg = 2, .bit = 13}
#define FEATURE_XTPR         (struct cpu_features){.leaf = FEATURE_LEAF1, .reg = 2, .bit = 14}
#define FEATURE_PDCM         (struct cpu_features){.leaf = FEATURE_LEAF1, .reg = 2, .bit = 15}
#define FEATURE_PCID         (struct cpu_features){.leaf = FEATURE_LEAF1, .reg = 2, .bit = 17}
#define FEATURE_DCA          (struct cpu_features){.leaf = FEATURE_LEAF1, .reg = 2, .bit = 18}
#define FEATURE_SSE4_1       (struct cpu_features){.leaf = FEATURE_LEAF1, .reg = 2, .bit = 19}
#define FEATURE_SSE4_2       (struct cpu_features){.leaf = FEATURE_LEAF1, .reg = 2, .bit = 20}
#define FEATURE_X2APIC       (struct cpu_features){.leaf = FEATURE_LEAF1, .reg = 2, .bit = 21}
#define FEATURE_MOVBE        (struct cpu_features){.leaf = FEATURE_LEAF1, .reg = 2, .bit = 22}
#define FEATURE_POPCNT       (struct cpu_features){.leaf = FEATURE_LEAF1, .reg = 2, .bit = 23}
#define FEATURE_TSC_DEADLINE (struct cpu_features){.leaf = FEATURE_LEAF1, .reg = 2, .bit = 24}
#define FEATURE_AES          (struct cpu_features){.leaf = FEATURE_LEAF1, .reg = 2, .bit = 25}
#define FEATURE_XSAVE        (struct cpu_features){.leaf = FEATURE_LEAF1, .reg = 2, .bit = 26}
#define FEATURE_OSXSAVE      (struct cpu_features){.leaf = FEATURE_LEAF1, .reg = 2, .bit = 27}
#define FEATURE_AVX          (struct cpu_features){.leaf = FEATURE_LEAF1, .reg = 2, .bit = 28}
#define FEATURE_F16C         (struct cpu_features){.leaf = FEATURE_LEAF1, .reg = 2, .bit = 29}
#define FEATURE_RDRAND       (struct cpu_features){.leaf = FEATURE_LEAF1, .reg = 2, .bit = 30}

#define FEATURE_TURBO        (struct cpu_features){.leaf = FEATURE_LEAF6, .reg = 0, .bit = 1}
#define FEATURE_HWP          (struct cpu_features){.leaf = FEATURE_LEAF6, .reg = 0, .bit = 7}
#define FEATURE_HWP_PREF     (struct cpu_features){.leaf = FEATURE_LEAF6, .reg = 0, .bit = 10}
#define FEATURE_HWP_PKG      (struct cpu_features){.leaf = FEATURE_LEAF6, .reg = 0, .bit = 11}
#define FEATURE_HWP_REQ_FAST (struct cpu_features){.leaf = FEATURE_LEAF6, .reg = 0, .bit = 18}
#define FEATURE_MPERFAPERF   (struct cpu_features){.leaf = FEATURE_LEAF6, .reg = 2, .bit = 0}
#define FEATURE_EPB          (struct cpu_features){.leaf = FEATURE_LEAF6, .reg = 2, .bit = 3}

#define FEATURE_FSGSBASE          (struct cpu_features){.leaf = FEATURE_LEAF7, .reg = 1, .bit = 0}
#define FEATURE_SGX               (struct cpu_features){.leaf = FEATURE_LEAF7, .reg = 1, .bit = 2}
#define FEATURE_BMI1              (struct cpu_features){.leaf = FEATURE_LEAF7, .reg = 1, .bit = 3}
#define FEATURE_HLE               (struct cpu_features){.leaf = FEATURE_LEAF7, .reg = 1, .bit = 4}
#define FEATURE_AVX2              (struct cpu_features){.leaf = FEATURE_LEAF7, .reg = 1, .bit = 5}
#define FEATURE_SMEP              (struct cpu_features){.leaf = FEATURE_LEAF7, .reg = 1, .bit = 7}
#define FEATURE_BMI2              (struct cpu_features){.leaf = FEATURE_LEAF7, .reg = 1, .bit = 8}
#define FEATURE_ERMS              (struct cpu_features){.leaf = FEATURE_LEAF7, .reg = 1, .bit = 9}
#define FEATURE_INVPCID           (struct cpu_features){.leaf = FEATURE_LEAF7, .reg = 1, .bit = 10}
#define FEATURE_RTM               (struct cpu_features){.leaf = FEATURE_LEAF7, .reg = 1, .bit = 11}
#define FEATURE_PQM               (struct cpu_features){.leaf = FEATURE_LEAF7, .reg = 1, .bit = 12}
#define FEATURE_PQE               (struct cpu_features){.leaf = FEATURE_LEAF7, .reg = 1, .bit = 15}
#define FEATURE_AVX512F           (struct cpu_features){.leaf = FEATURE_LEAF7, .reg = 1, .bit = 16}
#define FEATURE_AVX512DQ          (struct cpu_features){.leaf = FEATURE_LEAF7, .reg = 1, .bit = 17}
#define FEATURE_RDSEED            (struct cpu_features){.leaf = FEATURE_LEAF7, .reg = 1, .bit = 18}
#define FEATURE_ADX               (struct cpu_features){.leaf = FEATURE_LEAF7, .reg = 1, .bit = 19}
#define FEATURE_SMAP              (struct cpu_features){.leaf = FEATURE_LEAF7, .reg = 1, .bit = 20}
#define FEATURE_AVX512IFMA        (struct cpu_features){.leaf = FEATURE_LEAF7, .reg = 1, .bit = 21}
#define FEATURE_CLWB              (struct cpu_features){.leaf = FEATURE_LEAF7, .reg = 1, .bit = 24}
#define FEATURE_INTEL_PT          (struct cpu_features){.leaf = FEATURE_LEAF7, .reg = 1, .bit = 25}
#define FEATURE_AVX512PF          (struct cpu_features){.leaf = FEATURE_LEAF7, .reg = 1, .bit = 26}
#define FEATURE_AVX512ER          (struct cpu_features){.leaf = FEATURE_LEAF7, .reg = 1, .bit = 27}
#define FEATURE_AVX512CD          (struct cpu_features){.leaf = FEATURE_LEAF7, .reg = 1, .bit = 28}
#define FEATURE_SHA               (struct cpu_features){.leaf = FEATURE_LEAF7, .reg = 1, .bit = 29}
#define FEATURE_AVX512BW          (struct cpu_features){.leaf = FEATURE_LEAF7, .reg = 1, .bit = 30}
#define FEATURE_AVX512VL          (struct cpu_features){.leaf = FEATURE_LEAF7, .reg = 1, .bit = 31}
#define FEATURE_PREFETCHWT1       (struct cpu_features){.leaf = FEATURE_LEAF7, .reg = 2, .bit = 0}
#define FEATURE_AVX512VBMI        (struct cpu_features){.leaf = FEATURE_LEAF7, .reg = 2, .bit = 1}
#define FEATURE_UMIP              (struct cpu_features){.leaf = FEATURE_LEAF7, .reg = 2, .bit = 2}
#define FEATURE_PKU               (struct cpu_features){.leaf = FEATURE_LEAF7, .reg = 2, .bit = 3}
#define FEATURE_AVX512VBMI2       (struct cpu_features){.leaf = FEATURE_LEAF7, .reg = 2, .bit = 6}
#define FEATURE_GFNI              (struct cpu_features){.leaf = FEATURE_LEAF7, .reg = 2, .bit = 8}
#define FEATURE_VAES              (struct cpu_features){.leaf = FEATURE_LEAF7, .reg = 2, .bit = 9}
#define FEATURE_VPCLMULQDQ        (struct cpu_features){.leaf = FEATURE_LEAF7, .reg = 2, .bit = 10}
#define FEATURE_AVX512VNNI        (struct cpu_features){.leaf = FEATURE_LEAF7, .reg = 2, .bit = 11}
#define FEATURE_AVX512BITALG      (struct cpu_features){.leaf = FEATURE_LEAF7, .reg = 2, .bit = 12}
#define FEATURE_AVX512VPOPCNTDQ   (struct cpu_features){.leaf = FEATURE_LEAF7, .reg = 2, .bit = 14}
#define FEATURE_LA57              (struct cpu_features){.leaf = FEATURE_LEAF7, .reg = 2, .bit = 17}
#define FEATURE_RDPID             (struct cpu_features){.leaf = FEATURE_LEAF7, .reg = 2, .bit = 22}
#define FEATURE_AVX512_4VNNIW     (struct cpu_features){.leaf = FEATURE_LEAF7, .reg = 3, .bit = 2}
#define FEATURE_AVX512_4FMAPS     (struct cpu_features){.leaf = FEATURE_LEAF7, .reg = 3, .bit = 3}
#define FEATURE_MD_CLEAR          (struct cpu_features){.leaf = FEATURE_LEAF7, .reg = 3, .bit = 10}
#define FEATURE_CLFLUSH           (struct cpu_features){.leaf = FEATURE_LEAF7, .reg = 3, .bit = 19}
#define FEATURE_ARCH_CAPABILITIES (struct cpu_features){.leaf = FEATURE_LEAF7, .reg = 3, .bit = 29}

#define FEATURE_LAHF    (struct cpu_features){.leaf = FEATURE_LEAF8_01, .reg = 2, .bit = 0}
#define FEATURE_SYSCALL (struct cpu_features){.leaf = FEATURE_LEAF8_01, .reg = 3, .bit = 11}
#define FEATURE_XD      (struct cpu_features){.leaf = FEATURE_LEAF8_01, .reg = 3, .bit = 20}
#define FEATURE_PDPE1GB (struct cpu_features){.leaf = FEATURE_LEAF8_01, .reg = 3, .bit = 26}
#define FEATURE_RDTSCP  (struct cpu_features){.leaf = FEATURE_LEAF8_01, .reg = 3, .bit = 27}

#define FEATURE_CPB (struct cpu_features){.leaf = FEATURE_LEAF8_07, .reg = 3, .bit = 9}

typedef struct {
    uint32_t eax;
    uint32_t ebx;
    uint32_t ecx;
    uint32_t edx;
} cpuid_registers_t;

typedef enum {
    FEATURE_LEAF1 = 0,
    FEATURE_LEAF6,
    FEATURE_LEAF7,
    FEATURE_LEAF8_01,
    FEATURE_LEAF8_07,
    FEATURE_COUNT,
} features_leaf_t;

struct cpu_features {
    uint8_t leaf;
    uint8_t reg;
    uint8_t bit;
};

void cpu_read_features(void);
bool cpu_has_feature(struct cpu_features feat);

#endif