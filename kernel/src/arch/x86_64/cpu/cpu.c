#include "cpu/cpu.h"

#include <stdio.h>
#include <string.h>

#include "arch.h"
#include "libs/log.h"

static cpuid_registers_t leaves[FEATURE_COUNT];
static cpu_info_t boot_cpu_info = {};
static uint32_t max_leaf        = 0;

static inline cpuid_registers_t call_cpuid(uint32_t leaf, uint32_t subleaf) {
    cpuid_registers_t res;
    asm volatile("cpuid"
                 : "=a"(res.eax), "=b"(res.ebx), "=c"(res.ecx), "=d"(res.edx)
                 : "a"(leaf), "c"(subleaf));
    return res;
}

void cpu_init(void) {
    cpuid_registers_t regs = call_cpuid(0, 0);
    max_leaf               = regs.eax;

    memcpy(boot_cpu_info.vendor_id, &regs.ebx, 4);
    memcpy(boot_cpu_info.vendor_id + 4, &regs.edx, 4);
    memcpy(boot_cpu_info.vendor_id + 8, &regs.ecx, 4);

    if (max_leaf >= 1) {
        regs                  = call_cpuid(1, 0);
        leaves[FEATURE_LEAF1] = regs;

        boot_cpu_info.stepping = regs.eax & 0xf;
        uint32_t base_model    = (regs.eax >> 4) & 0xf;
        uint32_t base_family   = (regs.eax >> 8) & 0xf;

        boot_cpu_info.family =
            (base_family == 0xf) ? base_family + ((regs.eax >> 20) & 0xff) : base_family;
        boot_cpu_info.model = (base_family == 0x6 || base_family == 0xf)
                                  ? base_model + (((regs.eax >> 16) & 0xf) << 4)
                                  : base_model;

        boot_cpu_info.has_hw_virt    = cpu_has_feature(FEATURE_VMX);
        boot_cpu_info.is_virtualized = cpu_has_feature(FEATURE_HYPERVISOR);
    }

    if (max_leaf >= 7) {
        leaves[FEATURE_LEAF6] = call_cpuid(6, 0);
        leaves[FEATURE_LEAF7] = call_cpuid(7, 0);
    }

    if (boot_cpu_info.is_virtualized) {
        regs = call_cpuid(0x40000000, 0);

        memcpy(boot_cpu_info.hypervisor_vendor, &regs.ebx, 4);
        memcpy(boot_cpu_info.hypervisor_vendor + 4, &regs.ecx, 4);
        memcpy(boot_cpu_info.hypervisor_vendor + 8, &regs.edx, 4);
    }

    regs                  = call_cpuid(0x80000000, 0);
    uint32_t max_ext_leaf = regs.eax;

    if (max_ext_leaf >= 0x80000001) {
        regs                     = call_cpuid(0x80000001, 0);
        leaves[FEATURE_LEAF8_01] = regs;

        bool has_svm              = cpu_has_feature(FEATURE_SVM);
        boot_cpu_info.has_hw_virt = boot_cpu_info.has_hw_virt || has_svm;
    }

    if (max_ext_leaf >= 0x80000004) {
        uint32_t brand_leaves[3] = {0x80000002, 0x80000003, 0x80000004};

        for (size_t i = 0; i < 3; ++i) {
            regs = call_cpuid(brand_leaves[i], 0);

            memcpy(boot_cpu_info.brand_string + (i * 16), &regs.eax, 4);
            memcpy(boot_cpu_info.brand_string + (i * 16) + 4, &regs.ebx, 4);
            memcpy(boot_cpu_info.brand_string + (i * 16) + 8, &regs.ecx, 4);
            memcpy(boot_cpu_info.brand_string + (i * 16) + 12, &regs.edx, 4);
        }

        boot_cpu_info.brand_string[48] = '\0';
    }

    if (max_ext_leaf >= 0x80000007) {
        regs                     = call_cpuid(0x80000007, 0);
        leaves[FEATURE_LEAF8_07] = regs;
    }
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

bool cpu_has_subfeature(struct cpu_subfeatures feat) {
    cpuid_registers_t leaf = call_cpuid(feat.leaf, feat.subleaf);

    switch (feat.reg) {
        case 0:
            return leaf.eax & (1u << feat.bit);
        case 1:
            return leaf.ebx & (1u << feat.bit);
        case 2:
            return leaf.ecx & (1u << feat.bit);
        case 3:
            return leaf.edx & (1u << feat.bit);
        default:
            PANIC("Unknown CPUID register %d", feat.reg);
    }
}

cpuid_registers_t cpu_read_value(uint32_t leaf) {
    return call_cpuid(leaf, 0);
}

cpuid_registers_t cpu_read_subleaf_value(uint32_t leaf, uint32_t subleaf) {
    return call_cpuid(leaf, subleaf);
}

const cpu_info_t* get_cpu_info(void) {
    return &boot_cpu_info;
}

void cpu_print_info(void) {
    const cpu_info_t* cpu = get_cpu_info();

    char simd_str[128] = {0};
    int offset         = 0;

#define APPEND_SIMD(...)                                                                       \
    do {                                                                                       \
        if (sizeof(simd_str) > (size_t)offset) {                                               \
            int written = snprintf(simd_str + offset, sizeof(simd_str) - offset, __VA_ARGS__); \
            if (written > 0) offset += written;                                                \
        }                                                                                      \
    } while (0)

    if (cpu_has_feature(FEATURE_SSE)) {
        APPEND_SIMD("SSE ");
    }

    if (cpu_has_feature(FEATURE_SSE2)) {
        APPEND_SIMD("SSE2 ");
    }

    if (cpu_has_feature(FEATURE_AVX)) {
        APPEND_SIMD("AVX ");
    }

    if (cpu_has_feature(FEATURE_AVX2)) {
        APPEND_SIMD("AVX2 ");
    }

    if (cpu_has_feature(FEATURE_AVX512F)) {
        APPEND_SIMD("AVX-512 ");
    }

#undef APPEND_SIMD

    char buffer[512] = {};
    snprintf(
        buffer,
        sizeof(buffer),
        "=== Hardware Information ===\n"
        "Vendor     : %s\n"
        "Brand      : %s\n"
        "Fam/Mod/St : %u / %u / %u\n"
        "\n--- Execution Environment ---\n"
        "Mode       : %s\n"
        "Hypervisor : %s\n"
        "\n--- Instruction set ---\n"
        "SIMD       : %s\n"
        "HW Virt    : %s\n"
        "HyperThread: %s\n",
        cpu->vendor_id,
        cpu->brand_string,
        cpu->family,
        cpu->model,
        cpu->stepping,
        cpu->is_virtualized ? "Virtualized" : "Bare Metal",
        cpu->is_virtualized ? cpu->hypervisor_vendor : "N/A",
        simd_str[0] != '\0' ? simd_str : "None",
        cpu->has_hw_virt ? "Supported" : "Not Supported",
        cpu->has_htt ? "Supported" : "Not Supported"
    );

    arch_write(TARGET_FRAMEBUFFER, buffer);
}