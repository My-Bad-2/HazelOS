#ifndef KERNEL_LIBS_SPINLOCK_H
#define KERNEL_LIBS_SPINLOCK_H 1

#include <stdatomic.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define lock_acquire(l) \
    _Generic((l), spinlock_t*: acquire_spinlock, qspinlock_t*: acquire_qspinlock)(l)

#define lock_release(l) \
    _Generic((l), spinlock_t*: release_spinlock, qspinlock_t*: release_qspinlock)(l)

#define lock_try_acquire(l) \
    _Generic((l), \
    spinlock_t*:   test_spinlock, \
    qspinlock_t*:  try_acquire_qspinlock \
)(l)

#define lock_acquire_irq(l) \
    _Generic((l), spinlock_t*: acquire_interrupt_lock, qspinlock_t*: acquire_qinterrupt_lock)(l)

#define lock_release_irq(l, state)                                                             \
    _Generic((l), spinlock_t*: release_interrupt_lock, qspinlock_t*: release_qinterrupt_lock)( \
        l,                                                                                     \
        state                                                                                  \
    )
typedef struct {
    atomic_size_t next;
    atomic_size_t owner;
} spinlock_t;

void create_spinlock(spinlock_t* lock);
void acquire_spinlock(spinlock_t* lock);
void release_spinlock(spinlock_t* lock);
bool test_spinlock(spinlock_t* lock);

[[nodiscard]] size_t acquire_interrupt_lock(spinlock_t* lock);
void release_interrupt_lock(spinlock_t* lock, size_t irq_state);

#define MAX_QSPIN_NODES 4

struct [[gnu::aligned(CACHE_LINE_SIZE)]] mcs_node {
    atomic_uintptr_t next;
    atomic_uint locked;
};

typedef struct {
    _Atomic(uint64_t) val;
} qspinlock_t;

void qspinlock_init(void);

void create_qspinlock(qspinlock_t* lock);
bool try_acquire_qspinlock(qspinlock_t* lock);
void acquire_qspinlock(qspinlock_t* lock);
void release_qspinlock(qspinlock_t* lock);
bool test_qspinlock(qspinlock_t* lock);

[[nodiscard]] size_t acquire_qinterrupt_lock(qspinlock_t* lock);
void release_qinterrupt_lock(qspinlock_t* lock, size_t irq_state);

typedef struct {
    atomic_uint counts;
    qspinlock_t wait_lock;
} rwlock_t;

void create_rwlock(rwlock_t* lock);
bool test_rwlock(rwlock_t* lock);

void acquire_read(rwlock_t* lock);
void acquire_write(rwlock_t* lock);

void release_read(rwlock_t* lock);
void release_write(rwlock_t* lock);

#ifdef __cplusplus
}
#endif

#endif