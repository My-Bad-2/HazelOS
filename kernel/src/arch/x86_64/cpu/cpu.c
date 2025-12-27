#include "cpu/cpu.h"

#include <cpuid.h>

#include "libs/log.h"

static cpuid_registers_t leaves[FEATURE_COUNT];

static inline cpuid_registers_t call_cpuid(uint32_t leaf, uint32_t subleaf) {
    cpuid_registers_t res;
    asm volatile("cpuid"
                 : "=a"(res.eax), "=b"(res.ebx), "=c"(res.ecx), "=d"(res.edx)
                 : "a"(leaf), "c"(subleaf));
    return res;
}

void cpu_read_features(void) {
    leaves[FEATURE_LEAF1]    = call_cpuid(1, 0);
    leaves[FEATURE_LEAF6]    = call_cpuid(6, 0);
    leaves[FEATURE_LEAF7]    = call_cpuid(7, 0);
    leaves[FEATURE_LEAF8_01] = call_cpuid(0x80000001, 0);
    leaves[FEATURE_LEAF1]    = call_cpuid(0x80000007, 0);
}

bool cpu_has_feature(struct cpu_features feat) {
    cpuid_registers_t* leaf = &leaves[feat.leaf];

    switch (feat.reg) {
        case 0:
            return leaf->eax & (1u << feat.bit);
        case 1:
            return leaf->ebx & (1u << feat.bit);
        case 2:
            return leaf->ecx & (1u << feat.bit);
        case 3:
            return leaf->edx & (1u << feat.bit);
        default:
            PANIC("Unknown CPUID register %d", feat.reg);
    }
}