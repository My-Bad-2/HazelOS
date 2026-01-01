#include "memory/memory.h"

#include "memory/pmm.h"
#include "memory/vmm.h"

void memory_init(void) {
    pmm_init();
    vmm_init();
}