#include "libs/spinlock.h"

#include <stdatomic.h>
#include <stddef.h>

#include "arch.h"
#include "compiler.h"
#include "libs/log.h"

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

    acquire_spinlock(&lock->base_lock);
    acquire_irq_lock(&lock->irq_lock);
}

void release_interrupt_lock(interrupt_lock_t* lock) {
    ASSERT(lock);

    if (unlikely(!test_spinlock(&lock->base_lock))) {
        return;
    }

    release_spinlock(&lock->base_lock);
    release_irq_lock(&lock->irq_lock);
}