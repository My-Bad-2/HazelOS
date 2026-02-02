#include "libs/spinlock.h"

#include <stdatomic.h>
#include <stddef.h>

#include "arch.h"
#include "compiler.h"
#include "libs/log.h"

#define WRITER_ACTIVE_MASK  (1u << 1)
#define WRITER_WAITING_UNIT (1u << 2)
#define WRITER_WAITING_MASK (0x1fffc)

#define READER_UNIT (1u << 17)
#define READER_MASK (0xFFFE0000)

void create_spinlock(spinlock_t* lock) {
    ASSERT(lock);

    lock->owner = 0;
    lock->next  = 0;
}

void acquire_spinlock(spinlock_t* lock) {
    ASSERT(lock);

    size_t curr = atomic_fetch_add_explicit(&lock->next, 1, memory_order_relaxed);

    while (atomic_load_explicit(&lock->owner, memory_order_acquire) != curr) {
        arch_pause();
    }
}

bool test_spinlock(spinlock_t* lock) {
    ASSERT(lock);

    size_t curr = atomic_load_explicit(&lock->owner, memory_order_relaxed);
    size_t next = atomic_load_explicit(&lock->next, memory_order_relaxed);

    return curr != next;
}

void release_spinlock(spinlock_t* lock) {
    ASSERT(lock);

    if (unlikely(!test_spinlock(lock))) {
        return;
    }

    size_t curr = atomic_load_explicit(&lock->owner, memory_order_relaxed);
    atomic_fetch_add_explicit(&lock->owner, 1, memory_order_release);
}

void acquire_irq_lock(irq_lock_t* lock) {
    ASSERT(lock);

    lock->flags = arch_save_flags();
    arch_disable_interrupts();
}

void release_irq_lock(irq_lock_t* lock) {
    ASSERT(lock);

    // Restore the state exactly as it was before we acquired the lock
    arch_restore_flags(lock->flags);
}

void create_interrupt_lock(interrupt_lock_t* lock) {
    ASSERT(lock);

    create_spinlock(&lock->base_lock);
    create_irq_lock(&lock->irq_lock);
}

void acquire_interrupt_lock(interrupt_lock_t* lock) {
    ASSERT(lock);

    acquire_irq_lock(&lock->irq_lock);
    acquire_spinlock(&lock->base_lock);
}

void release_interrupt_lock(interrupt_lock_t* lock) {
    ASSERT(lock);

    if (unlikely(!test_spinlock(&lock->base_lock))) {
        return;
    }

    release_spinlock(&lock->base_lock);
    release_irq_lock(&lock->irq_lock);
}

void create_rwlock(rwlock_t* lock) {
    atomic_init(&lock->state, 0);
}

void acquire_read(rwlock_t* lock) {
    while (true) {
        uint32_t curr = atomic_load_explicit(&lock->state, memory_order_relaxed);

        if (curr & (WRITER_ACTIVE_MASK | WRITER_WAITING_MASK)) {
            arch_pause();
            continue;
        }

        if (atomic_compare_exchange_weak_explicit(
                &lock->state,
                &curr,
                curr + READER_UNIT,
                memory_order_acquire,
                memory_order_relaxed
            )) {
            return;
        }
    }
}

void release_read(rwlock_t* lock) {
    atomic_fetch_sub_explicit(&lock->state, READER_UNIT, memory_order_release);
}

void acquire_write(rwlock_t* lock) {
    atomic_fetch_add_explicit(&lock->state, WRITER_WAITING_UNIT, memory_order_acquire);

    while (true) {
        uint32_t curr = atomic_load_explicit(&lock->state, memory_order_relaxed);

        if ((curr & READER_MASK) == 0 && (curr & WRITER_ACTIVE_MASK) == 0) {
            uint32_t next = (curr - WRITER_WAITING_UNIT) | WRITER_ACTIVE_MASK;

            if (atomic_compare_exchange_weak_explicit(
                    &lock->state,
                    &curr,
                    next,
                    memory_order_acquire,
                    memory_order_relaxed
                )) {
                return;
            }
        } else {
            arch_pause();
        }
    }
}

void release_write(rwlock_t* lock) {
    atomic_fetch_and_explicit(&lock->state, ~WRITER_ACTIVE_MASK, memory_order_release);
}

bool test_rwlock(rwlock_t* lock) {
    return (atomic_load_explicit(&lock->state, memory_order_relaxed) == 0);
}