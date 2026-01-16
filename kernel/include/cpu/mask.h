#ifndef KERNEL_CPU_MASK_H
#define KERNEL_CPU_MASK_H 1

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    uint64_t* bits;
    size_t size;
} cpu_mask_t;

void cpumask_alloc(cpu_mask_t* mask);
void cpumask_free(cpu_mask_t* mask);
void cpumask_copy(cpu_mask_t* dest, const cpu_mask_t* src);

void cpumask_clear(cpu_mask_t* mask);

static inline void cpumask_set(cpu_mask_t* mask, size_t cpu_id) {
    if (cpu_id >= mask->size) {
        return;
    }

    mask->bits[cpu_id / 64] |= (1ul << (cpu_id % 64));
}

static inline void cpumask_clear_cpu(cpu_mask_t* mask, size_t cpu_id) {
    if (cpu_id >= mask->size) {
        return;
    }

    mask->bits[cpu_id / 64] &= ~(1ul << (cpu_id % 64));
}

static inline bool cpumask_test(const cpu_mask_t* mask, size_t cpu_id) {
    if (cpu_id >= mask->size) {
        return false;
    }

    return (mask->bits[cpu_id / 64] & (1ul << (cpu_id % 64))) != 0;
}

#ifdef __cplusplus
}
#endif

#endif