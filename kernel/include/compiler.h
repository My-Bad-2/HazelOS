#ifndef KERNEL_COMPILER_H
#define KERNEL_COMPILER_H 1

#if __has_builtin(__builtin_expect)
#define likely(x)   __builtin_expect(!!(x), true)
#define unlikely(x) __builtin_expect(!!(x), false)
#else
#define likely(x)   (x)
#define unlikely(x) (x)
#endif

#endif