#include "libs/spinlock.h"

#include <stdatomic.h>
#include <stddef.h>

#include "arch.h"
#include "compiler.h"

void create_spinlock(spinlock_t* lock) {
    if (unlikely(!lock)) {
        return;
    }

    lock->owner = 0;
    lock->next  = 0;
}

void acquire_spinlock(spinlock_t* lock) {
    if (unlikely(!lock)) {
        return;
    }

    size_t curr = atomic_fetch_add_explicit(&lock->next, 1, memory_order_relaxed);

    while (atomic_load_explicit(&lock->owner, memory_order_acquire) != curr) {
        arch_pause();
    }
}

bool test_spinlock(spinlock_t* lock) {
    if (unlikely(!lock)) {
        return false;
    }

    size_t curr = atomic_load_explicit(&lock->owner, memory_order_relaxed);
    size_t next = atomic_load_explicit(&lock->next, memory_order_relaxed);

    return curr != next;
}

void release_spinlock(spinlock_t* lock) {
    if (unlikely(!lock)) {
        return;
    }

    if (unlikely(!test_spinlock(lock))) {
        return;
    }

    size_t curr = atomic_load_explicit(&lock->owner, memory_order_relaxed);
    atomic_fetch_add_explicit(&lock->owner, 1, memory_order_release);
}

void acquire_interrupt_lock(interrupt_lock_t* lock) {
    if (unlikely(!lock)) {
        return;
    }

    lock->flags = arch_save_flags();
    acquire_spinlock(&lock->base_lock);
    arch_disable_interrupts();
}

void release_interrupt_lock(interrupt_lock_t* lock) {
    if (unlikely(!lock)) {
        return;
    }

    if (unlikely(!test_spinlock(&lock->base_lock))) {
        return;
    }

    release_spinlock(&lock->base_lock);

    // Restore the state exactly as it was before we acquired the lock
    arch_restore_flags(lock->flags);
}