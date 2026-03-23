#include <stdatomic.h>

#include "arch.h"
#include "compiler.h"
#include "libs/log.h"
#include "libs/spinlock.h"

// Bitfield Layout:
// [31:8] Reader Count: Support upto 16.7 million concurrent readers (that's a lot)
// [7:0]  Writer Locked Byte (0xff -> writer is active/waiting)
#define QW_LOCKED 0xffu
#define QR_SHIFT  8
#define QR_BIAS   (1U << QR_SHIFT)

void create_rwlock(rwlock_t* lock) {
    atomic_init(&lock->counts, 0);
    create_qspinlock(&lock->wait_lock);
}

void acquire_read(rwlock_t* lock) {
    ASSERT(lock);

    while (true) {
        uint32_t counts = atomic_fetch_add_explicit(&lock->counts, QR_BIAS, memory_order_relaxed);

        if (likely((counts & QW_LOCKED) == 0)) {
            return;
        }

        atomic_fetch_sub_explicit(&lock->counts, QR_BIAS, memory_order_relaxed);

        while (atomic_load_explicit(&lock->counts, memory_order_relaxed) & QW_LOCKED) {
            arch_pause();
        }
    }
}

void release_read(rwlock_t* lock) {
    ASSERT(lock);
    atomic_fetch_sub_explicit(&lock->counts, QR_BIAS, memory_order_release);
}

void acquire_write(rwlock_t* lock) {
    ASSERT(lock);

    // Serialize with other writers
    acquire_qspinlock(&lock->wait_lock);

    // Block any new readers from acquiring the lock
    atomic_fetch_or_explicit(&lock->counts, QW_LOCKED, memory_order_acquire);

    // Wait for all currently active readers to drain
    while (atomic_load_explicit(&lock->counts, memory_order_relaxed) != QW_LOCKED) {
        arch_pause();
    }
}

void release_write(rwlock_t* lock) {
    ASSERT(lock);

    // Unblock any waiting reader
    atomic_fetch_and_explicit(&lock->counts, ~QW_LOCKED, memory_order_release);

    // Hand off the writer lock to the next writer in the MCS queue.
    release_qspinlock(&lock->wait_lock);
}

bool test_rwlock(rwlock_t* lock) {
    ASSERT(lock);
    return (atomic_load_explicit(&lock->counts, memory_order_relaxed) == 0);
}