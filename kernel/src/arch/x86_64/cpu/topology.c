#include "cpu/cpu.h"
#include "cpu/mask.h"
#include "cpu/registers.h"
#include "cpu/smp.h"

void topology_detect(per_cpu_data_t* cpu) {
    uint32_t leaf = CPUID_EXTENDED_TOPOLOGY;

    cpuid_registers_t regs = cpu_read_value(0);
    if (regs.eax >= CPUID_V2_EXTENDED_TOPOLOGY) {
        regs = cpu_read_value(CPUID_V2_EXTENDED_TOPOLOGY);

        if (regs.ebx != 0) {
            leaf = CPUID_V2_EXTENDED_TOPOLOGY;
        }
    }

    regs          = cpu_read_value(leaf);
    uint32_t apic = regs.edx;

    uint32_t smt_shift    = 0;
    uint32_t core_shift   = 0;
    uint32_t module_shift = 0;
    uint32_t tile_shift   = 0;
    uint32_t die_shift    = 0;

    // We iterate up to 6 levels to be safe (SMT, Core, Module, Tile, Die, Pkg)
    for (uint32_t i = 0; i < 6; ++i) {
        regs = cpu_read_subleaf_value(leaf, i);

        uint32_t type  = (regs.ecx >> 8) & 0xff;
        uint32_t shift = regs.eax & 0x1f;

        if (type == CPUID_TOPOLOGY_LEVEL_INVALID) {
            break;
        }

        switch (type) {
            case CPUID_TOPOLOGY_LEVEL_SMT:
                smt_shift = shift;
                break;
            case CPUID_TOPOLOGY_LEVEL_CORE:
                core_shift = shift;
                break;
            case CPUID_TOPOLOGY_LEVEL_MODULE:
                module_shift = shift;
                break;
            case CPUID_TOPOLOGY_LEVEL_TILE:
                tile_shift = shift;
                break;
            case CPUID_TOPOLOGY_LEVEL_DIE:
                die_shift = shift;
                break;
            default:
                break;
        }
    }

    if (module_shift < core_shift) {
        module_shift = core_shift;
    }

    if (tile_shift < module_shift) {
        tile_shift = module_shift;
    }

    if (die_shift < tile_shift) {
        die_shift = tile_shift;
    }

    if (die_shift == 0) {
        die_shift = core_shift;
    }

    cpu->topology.apic_id   = apic;
    cpu->topology.smt_id    = apic & ((1 << smt_shift) - 1);
    cpu->topology.core_id   = (apic >> smt_shift) & ((1 << (core_shift - smt_shift)) - 1);
    cpu->topology.module_id = (apic >> core_shift) & ((1 << (module_shift - core_shift)) - 1);
    cpu->topology.tile_id   = (apic >> module_shift) & ((1 << (tile_shift - module_shift)) - 1);
    cpu->topology.socket_id = apic >> core_shift;
    cpu->topology.l3_id     = apic >> die_shift;
}

void topology_init_masks(per_cpu_data_t** all_cpus, size_t count) {
    for (size_t i = 0; i < count; ++i) {
        cpumask_alloc(&all_cpus[i]->topology.core_siblings);
        cpumask_alloc(&all_cpus[i]->topology.llc_siblings);
    }
}

void topology_map_siblings(per_cpu_data_t** all_cpus, size_t count) {
    for (size_t i = 0; i < count; ++i) {
        per_cpu_data_t* cpu_a = all_cpus[i];

        cpumask_clear(&cpu_a->topology.core_siblings);
        cpumask_clear(&cpu_a->topology.llc_siblings);

        for (size_t j = 0; j < count; ++j) {
            struct per_cpu_data* cpu_b = all_cpus[j];

            if ((cpu_a->topology.socket_id == cpu_b->topology.socket_id) &&
                (cpu_a->topology.core_id == cpu_b->topology.core_id)) {
                cpumask_set(&cpu_a->topology.core_siblings, j);
            }

            if (cpu_a->topology.l3_id == cpu_b->topology.l3_id) {
                cpumask_set(&cpu_a->topology.llc_siblings, j);
            }
        }
    }
}