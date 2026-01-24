#ifndef USERLAND_SYSCALL_H
#define USERLAND_SYSCALL_H 1

#include <stdint.h>

// Magic vodoo shit
#define _SYS_NARGS_IMPL(_1, _2, _3, _4, _5, _6, N, ...) N
#define _SYS_NARGS(...) _SYS_NARGS_IMPL(__VA_ARGS__, 6, 5, 4, 3, 2, 1)

#define _SYS_CONCAT(A, B) A##B
#define _SYS_DISPATCH(N)  _SYS_CONCAT(__syscall_, N)

#define syscall(id, ...) _SYS_DISPATCH(_SYS_NARGS(__VA_ARGS__))(id, __VA_ARGS__)

[[gnu::always_inline]] static inline long __syscall_0(long id) {
    long ret = 0;
    asm volatile("syscall" : "=a"(ret) : "a"(id) : "rcx", "r11", "memory");
    return ret;
}

[[gnu::always_inline]] static inline long __syscall_1(long id, long a1) {
    long ret = 0;
    asm volatile("syscall" : "=a"(ret) : "a"(id), "D"((uint64_t)a1) : "rcx", "r11", "memory");
    return ret;
}

[[gnu::always_inline]] static inline long __syscall_2(long id, long a1, long a2) {
    long ret = 0;

    asm volatile("syscall"
                 : "=a"(ret)
                 : "a"(id), "D"((uint64_t)a1), "S"((uint64_t)a2)
                 : "rcx", "r11", "memory");

    return ret;
}

[[gnu::always_inline]] static inline long __syscall_3(long id, long a1, long a2, long a3) {
    long ret = 0;

    asm volatile("syscall"
                 : "=a"(ret)
                 : "a"(id), "D"((uint64_t)a1), "S"((uint64_t)a2), "d"((uint64_t)a3)
                 : "rcx", "r11", "memory");

    return ret;
}

[[gnu::always_inline]] static inline long __syscall_4(long id, long a1, long a2, long a3, long a4) {
    long ret = 0;

    // Used instead of rcx (`syscall` destroys rcx and r11)
    register uint64_t r10 asm("r10") = (uint64_t)a4;

    asm volatile("syscall"
                 : "=a"(ret)
                 : "a"(id), "D"((uint64_t)a1), "S"((uint64_t)a2), "d"((uint64_t)a3), "r"(r10)
                 : "rcx", "r11", "memory");

    return ret;
}

[[gnu::always_inline]] static inline long
__syscall_5(long id, long a1, long a2, long a3, long a4, long a5) {
    long ret = 0;

    // Used instead of rcx (`syscall` destroys rcx and r11)
    register uint64_t r10 asm("r10") = (uint64_t)a4;
    register uint64_t r8 asm("r8")   = (uint64_t)a5;

    asm volatile(
        "syscall"
        : "=a"(ret)
        : "a"(id), "D"((uint64_t)a1), "S"((uint64_t)a2), "d"((uint64_t)a3), "r"(r10), "r"(r8)
        : "rcx", "r11", "memory"
    );

    return ret;
}

[[gnu::always_inline]] static inline long
__syscall_6(long id, long a1, long a2, long a3, long a4, long a5, long a6) {
    long ret = 0;

    // Used instead of rcx (`syscall` destroys rcx and r11)
    register uint64_t r10 asm("r10") = (uint64_t)a4;
    register uint64_t r8 asm("r8")   = (uint64_t)a5;
    register uint64_t r9 asm("r9")   = (uint64_t)a6;

    asm volatile("syscall"
                 : "=a"(ret)
                 : "a"(id),
                   "D"((uint64_t)a1),
                   "S"((uint64_t)a2),
                   "d"((uint64_t)a3),
                   "r"(r10),
                   "r"(r8),
                   "r"(r9)
                 : "rcx", "r11", "memory");

    return ret;
}

#endif