#include "compiler.h"
#include "cpu/registers.h"
#include "libs/spinlock.h"

void create_interrupt_lock(interrupt_lock_t* lock) {
    if (unlikely(!lock)) {
        return;
    }

    create_spinlock(&lock->base_lock);
    lock->flags = X86_FLAGS_RESERVED_ONES;
}