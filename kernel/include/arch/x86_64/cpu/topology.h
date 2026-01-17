#ifndef KERNEL_CPU_TOPOLOGY_H
#define KERNEL_CPU_TOPOLOGY_H 1

#include "cpu/mask.h"

struct cpu_topology {
    cpu_mask_t core_siblings;  // SMT threads on the same physical core
    cpu_mask_t llc_siblings;   // Cores sharing the same L3 cache

    uint32_t apic_id;    // Absolute hardware id
    uint32_t smt_id;     // Logical Thread ID (within Core)
    uint32_t core_id;    // Physical Core ID (within Socket)
    uint32_t module_id;  // Module/Cluster
    uint32_t tile_id;    // Physical Tile
    uint32_t socket_id;  // Physical Socket ID
    uint32_t l3_id;      // Last level cache id
};

#endif