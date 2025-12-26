#ifndef KERNEL_LIBS_SPINLOCK_H
#define KERNEL_LIBS_SPINLOCK_H 1

#include <stdatomic.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct spinlock {
    atomic_size_t next;
    atomic_size_t owner;
} spinlock_t;

void create_spinlock(spinlock_t* lock);
void acquire_spinlock(spinlock_t* lock);
void release_spinlock(spinlock_t* lock);
bool test_spinlock(spinlock_t* lock);

typedef struct irq_lock {
    size_t flags;
} irq_lock_t;

void create_irq_lock(irq_lock_t* lock);
void acquire_irq_lock(irq_lock_t* lock);
void release_irq_lock(irq_lock_t* lock);

typedef struct interrupt_lock {
    spinlock_t base_lock;
    irq_lock_t irq_lock;
} interrupt_lock_t;

void create_interrupt_lock(interrupt_lock_t* lock);
void acquire_interrupt_lock(interrupt_lock_t* lock);
void release_interrupt_lock(interrupt_lock_t* lock);

#ifdef __cplusplus
}
#endif

#endif