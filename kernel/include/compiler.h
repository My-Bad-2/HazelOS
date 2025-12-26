#ifndef KERNEL_COMPILER_H
#define KERNEL_COMPILER_H 1

#if __has_builtin(__builtin_expect)
#define likely(x)   __builtin_expect(!!(x), true)
#define unlikely(x) __builtin_expect(!!(x), false)
#else
#define likely(x)   (x)
#define unlikely(x) (x)
#endif

#if __has_builtin(__builtin_prefetch)
#define prefetch(addr, ...) __builtin_prefetch(addr, ##__VA_ARGS__)
#else
#define prefetch(addr, ...)
#endif

#if __has_builtin(__builtin_ctz)
#define ctz_unsafe(x)                                                                                                                                            \
    _Generic((x), unsigned long: __builtin_ctzl, unsigned long long: __builtin_ctzll, long: __builtin_ctzl, long long: __builtin_ctzll, default: __builtin_ctz)( \
        x                                                                                                                                                        \
    )
#define ctz(x) ((x) == 0 ? (sizeof(x) * 8) : ctz_unsafe(x))
#else
// TODO: Implement it
#define ctz(x)
#endif

#if __has_builtin(__builtin_popcount)
#define popcount(x)                                                                                                                                                                       \
    _Generic((x), unsigned long: __builtin_popcountl, unsigned long long: __builtin_popcountll, long: __builtin_popcountl, long long: __builtin_popcountll, default: __builtin_popcount)( \
        x                                                                                                                                                                                 \
    )
#else
// TODO: Implement it
#define popcount(x)
#endif

#endif