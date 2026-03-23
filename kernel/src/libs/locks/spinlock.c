#include "libs/spinlock.h"

#include <stdatomic.h>
#include <stddef.h>

#include "arch.h"
#include "compiler.h"
#include "libs/log.h"

void create_spinlock(spinlock_t* lock) {
    ASSERT(lock);

    atomic_init(&lock->owner, 0);
    atomic_init(&lock->next, 0);
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
    atomic_fetch_add_explicit(&lock->owner, 1, memory_order_release);
}

size_t acquire_interrupt_lock(spinlock_t* lock) {
    size_t flags = arch_save_flags();

    if (lock) {
        acquire_spinlock(lock);
    }

    arch_disable_interrupts();
    return flags;
}

void release_interrupt_lock(spinlock_t* lock, size_t flags) {
    if (lock) {
        if (unlikely(!test_spinlock(lock))) {
            return;
        }

        release_spinlock(lock);
    }

    arch_restore_flags(flags);
}