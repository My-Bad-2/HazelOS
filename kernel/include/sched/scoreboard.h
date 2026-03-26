#include "core/capability.h"
#ifndef KERNEL_SCHED_SCOREBOARD_H
#define KERNEL_SCHED_SCOREBOARD_H 1

#include <stdatomic.h>
#include <stdint.h>

#include "compiler.h"
#include "memory/memory.h"

// 134 Million Threads limit
#define SCOREBOARD_MAX_SCIDS 134217728
#define SCOREBOARD_RING_MASK (SCOREBOARD_MAX_SCIDS - 1)

#define U_STATE_EMPTY   0
#define U_STATE_READY   1
#define U_STATE_RUNNING 2
#define U_STATE_BLOCKED 3
#define U_STATE_DEAD    4

struct [[gnu::aligned(PAGE_SIZE_SMALL)]] sched_control {
    atomic_uint current_scid;
    atomic_uint highest_active_scid;

    atomic_uint ring_head;
    atomic_uint ring_tail;

    atomic_uint quantum_expired;
};

struct scoreboard {
    struct sched_control* ctrl;

    uint8_t* thread_states;
    _Atomic(uint8_t)* is_enqueued;
    _Atomic(uint32_t)* event_ring;
};

struct per_cpu_data;

void scoreboard_init(struct per_cpu_data* cpu, struct capability* daemon_vspace_cap);
uint32_t scoreboard_allocate_scid(struct per_cpu_data* cpu);

#endif