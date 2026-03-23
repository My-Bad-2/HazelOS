#include <stdint.h>

#include "arch.h"
#include "compiler.h"
#include "cpu/smp.h"
#include "libs/log.h"
#include "libs/spinlock.h"

// Bitfield Layout:
// [64:32] CPU ID: Allows upto 0xfffffffe, where 0 means "queue empty"
// [31:30] Context Index: 0-3 for Task, SoftIRQ, HardIRQ, NMI
// [29:16] Reserved
// [15:8]  Pending: The "next in line" flags
// [7:0]   Locked: The actual lock state

#define Q_LOCKED_OFFSET   0
#define Q_PENDING_OFFSET  8
#define Q_TAIL_IDX_OFFSET 30
#define Q_TAIL_CPU_OFFSET 32

#define Q_LOCKED_VAL          (1ul << Q_LOCKED_OFFSET)
#define Q_PENDING_VAL         (1ul << Q_PENDING_OFFSET)
#define Q_TAIL_IDX_MASK       (3ul << Q_TAIL_IDX_OFFSET)
#define Q_TAIL_CPU_MASK       (0xfffffffful << Q_TAIL_CPU_OFFSET)
#define Q_TAIL_MASK           (Q_TAIL_CPU_MASK | Q_TAIL_IDX_MASK)
#define Q_LOCKED_PENDING_MASK (Q_LOCKED_VAL | Q_PENDING_VAL)

void create_qspinlock(qspinlock_t* lock) {
    ASSERT(lock);
    atomic_init(&lock->val, 0);
}

static void qspin_lock(qspinlock_t* lock, uint64_t val) {
    if ((val & ~Q_LOCKED_VAL) == 0) {
        uint64_t expected = val;

        if (atomic_compare_exchange_strong_explicit(
                &lock->val,
                &expected,
                val | Q_PENDING_VAL,
                memory_order_acquire,
                memory_order_relaxed
            )) {
            while (atomic_load_explicit(&lock->val, memory_order_relaxed) & Q_LOCKED_VAL) {
                arch_pause();
            }

            atomic_fetch_add_explicit(
                &lock->val,
                Q_LOCKED_VAL - Q_PENDING_VAL,
                memory_order_acquire
            );
            return;
        }
    }

    per_cpu_data_t* cpu = smp_current_core();
    uint32_t idx        = cpu->qspin_node_idx++;
    if (unlikely(idx >= MAX_QSPIN_NODES)) {
        PANIC("QSpinlock context nesting exceeded MAX_QSPIN_NODES!");
    }

    struct mcs_node* node = &cpu->qspin_nodes[idx];
    atomic_init(&node->next, 0);
    atomic_init(&node->locked, 1);

    uint64_t tail = (((uint64_t)cpu->cpu_idx + 1ul) << Q_TAIL_CPU_OFFSET) |
                    (((uint64_t)idx) << Q_TAIL_IDX_OFFSET);

    uint64_t old_val = atomic_load_explicit(&lock->val, memory_order_relaxed);
    uint64_t new_val;
    do {
        new_val = (old_val & ~Q_TAIL_MASK) | tail;
    } while (!atomic_compare_exchange_weak_explicit(
        &lock->val,
        &old_val,
        new_val,
        memory_order_release,
        memory_order_relaxed
    ));

    if (old_val & Q_TAIL_MASK) {
        uint32_t prev_cpu = (uint32_t)(((old_val & Q_TAIL_CPU_MASK) >> Q_TAIL_CPU_OFFSET) - 1ul);
        uint32_t prev_idx = (uint32_t)((old_val & Q_TAIL_IDX_MASK) >> Q_TAIL_IDX_OFFSET);

        per_cpu_data_t* prev_cpu_data = smp_get_core(prev_cpu);
        struct mcs_node* prev         = &prev_cpu_data->qspin_nodes[prev_idx];

        atomic_store_explicit(&prev->next, (uintptr_t)node, memory_order_release);

        while (atomic_load_explicit(&node->locked, memory_order_acquire)) {
            arch_pause();
        }
    }

    while ((atomic_load_explicit(&lock->val, memory_order_relaxed) & Q_LOCKED_PENDING_MASK) != 0) {
        arch_pause();
    }

    uint64_t expected_tail = tail;
    if (atomic_compare_exchange_strong_explicit(
            &lock->val,
            &expected_tail,
            Q_LOCKED_VAL,
            memory_order_acquire,
            memory_order_relaxed
        )) {
        goto release_node;
    }

    atomic_fetch_or_explicit(&lock->val, Q_LOCKED_VAL, memory_order_acquire);

    while (atomic_load_explicit(&node->next, memory_order_relaxed) == 0) {
        arch_pause();
    }

    struct mcs_node* next_node =
        (struct mcs_node*)atomic_load_explicit(&node->next, memory_order_relaxed);
    atomic_store_explicit(&next_node->locked, 0, memory_order_release);

release_node:
    cpu->qspin_node_idx--;
}

void acquire_qspinlock(qspinlock_t* lock) {
    ASSERT(lock);
    uint64_t expected = 0;

    if (likely(atomic_compare_exchange_strong_explicit(
            &lock->val,
            &expected,
            Q_LOCKED_VAL,
            memory_order_acquire,
            memory_order_relaxed
        ))) {
        return;
    }

    qspin_lock(lock, expected);
}

void release_qspinlock(qspinlock_t* lock) {
    ASSERT(lock);
    atomic_fetch_sub_explicit(&lock->val, Q_LOCKED_VAL, memory_order_release);
}

bool test_qspinlock(qspinlock_t* lock) {
    ASSERT(lock);
    return (atomic_load_explicit(&lock->val, memory_order_relaxed) & Q_LOCKED_VAL) != 0;
}

size_t acquire_qinterrupt_lock(qspinlock_t* lock) {
    size_t flags = arch_save_flags();

    if (lock) {
        acquire_qspinlock(lock);
    }

    arch_disable_interrupts();
    return flags;
}

void release_qinterrupt_lock(qspinlock_t* lock, size_t flags) {
    if (lock) {
        if (unlikely(!test_qspinlock(lock))) {
            return;
        }

        release_qspinlock(lock);
    }

    arch_restore_flags(flags);
}