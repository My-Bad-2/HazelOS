#ifndef KERNEL_LIBS_MATH_H
#define KERNEL_LIBS_MATH_H 1

#include <stddef.h>

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

#endif