#include "libs/spinlock.h"

#include "cpu/registers.h"
#include "libs/log.h"

void create_irq_lock(irq_lock_t* lock) {
    ASSERT(lock);

    lock->flags = X86_FLAGS_RESERVED_ONES;
}