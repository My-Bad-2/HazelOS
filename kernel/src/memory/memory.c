#include "memory/memory.h"

#include "memory/heap.h"
#include "memory/pmm.h"
#include "memory/vma.h"
#include "memory/vmm.h"

void memory_init(void) {
    pmm_init();
    kheap_init();
    vmm_init();
    vma_cache_init();
}