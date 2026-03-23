#ifndef KERNEL_LIBS_MATH_H
#define KERNEL_LIBS_MATH_H 1

#include <limits.h>
#include <stddef.h>
#include <stdint.h>

#include "compiler.h"

#ifdef __cplusplus
extern "C" {
#endif

#define __bitmap_bits_per_elem(bitmap) (sizeof(*(bitmap)) * CHAR_BIT)
#define __bitmap_elem_idx(idx, bitmap) ((idx) / __bitmap_bits_per_elem(bitmap))
#define __bitmap_bit_idx(idx, bitmap)  ((idx) % __bitmap_bits_per_elem(bitmap))
#define __bitmap_bit_mask(idx, bitmap) ((typeof(*(bitmap)))1 << __bitmap_bit_idx(idx, bitmap))

#define __set_bit(idx, bitmap) \
    ((bitmap)[__bitmap_elem_idx(idx, bitmap)] |= __bitmap_bit_mask(idx, bitmap))

#define __clear_bit(idx, bitmap) \
    ((bitmap)[__bitmap_elem_idx(idx, bitmap)] &= ~__bitmap_bit_mask(idx, bitmap))

#define __test_bit(idx, bitmap) \
    ((bitmap)[__bitmap_elem_idx(idx, bitmap)] & __bitmap_bit_mask(idx, bitmap))

static inline size_t align_down(size_t n, size_t a) {
    return n & ~(a - 1);
}

static inline size_t align_up(size_t n, size_t a) {
    return align_down(n + a - 1, a);
}

static inline size_t div_roundup(size_t n, size_t a) {
    return align_up(n, a) / a;
}

static inline bool is_aligned(size_t n, size_t a) {
    return (n & (a - 1)) == 0;
}

static inline uint64_t muldiv64(uint64_t a, uint64_t b, uint64_t c) {
    uint128_t res = (uint128_t)a * b;
    return (uint64_t)(res / c);
}

#ifdef __cplusplus
}
#endif

#endif