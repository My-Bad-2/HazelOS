#include "cpu/mask.h"

#include <string.h>

#include "boot/boot.h"
#include "libs/math.h"
#include "memory/heap.h"

static kmem_cache_t* cpu_mask_cache = nullptr;

static inline size_t cpumask_size_bytes(size_t cpu_count) {
    size_t chunks = div_roundup(cpu_count, 64);
    return chunks * sizeof(uint64_t);
}

void cpumask_alloc(cpu_mask_t* mask) {
    const size_t cpu_count = mp_request.response->cpu_count;

    if (!cpu_mask_cache) {
        cpu_mask_cache = kmem_cache_create(
            "cpu_mask_cache",
            cpumask_size_bytes(cpu_count),
            cpumask_size_bytes(cpu_count),
            0,
            nullptr
        );
    }

    mask->size = cpu_count;
    mask->bits = (uint64_t*)kmem_cache_alloc(cpu_mask_cache);
}

void cpumask_free(cpu_mask_t* mask) {
    if (mask->bits) {
        kmem_cache_free(cpu_mask_cache, mask->bits);
        mask->bits = nullptr;
    }
}

void cpumask_copy(cpu_mask_t* dest, const cpu_mask_t* src) {
    if (dest->size != src->size) {
        return;
    }

    memcpy(dest->bits, src->bits, cpumask_size_bytes(src->size));
}

void cpumask_clear(cpu_mask_t* mask) {
    if (!mask->bits) {
        return;
    }

    memset(mask->bits, 0, cpumask_size_bytes(mask->size));
}