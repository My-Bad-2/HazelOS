#ifndef USERLAND_SYSCALL_H
#define USERLAND_SYSCALL_H 1

// Magic vodoo shit
#define __SYS_NARGS_X(a, b, c, d, e, f, g, n, ...) n
#define __SYS_NARGS(...) __SYS_NARGS_X(dummy, ##__VA_ARGS__, 6, 5, 4, 3, 2, 1, 0)

#define __SYS_CONCAT(A, B) A##B
#define __SYS_DISPATCH(N)  __SYS_CONCAT(__syscall_, N)

#define syscall(id, ...) __SYS_DISPATCH(__SYS_NARGS(__VA_ARGS__))(id, ##__VA_ARGS__)

[[gnu::always_inline]] static inline long __syscall_0(long id) {
    register long _rax asm("rax") = id;
    asm volatile("syscall" : "+r"(_rax) : : "rcx", "r11", "memory");
    return _rax;
}

[[gnu::always_inline]] static inline long __syscall_1(long id, long a1) {
    register long _rax asm("rax") = id;
    register long _rdi asm("rdi") = a1;
    asm volatile("syscall" : "+r"(_rax) : "r"(_rdi) : "rcx", "r11", "memory");
    return _rax;
}

[[gnu::always_inline]] static inline long __syscall_2(long id, long a1, long a2) {
    register long _rax asm("rax") = id;
    register long _rdi asm("rdi") = a1;
    register long _rsi asm("rsi") = a2;
    asm volatile("syscall" : "+r"(_rax) : "r"(_rdi), "r"(_rsi) : "rcx", "r11", "memory");
    return _rax;
}

[[gnu::always_inline]] static inline long __syscall_3(long id, long a1, long a2, long a3) {
    register long _rax asm("rax") = id;
    register long _rdi asm("rdi") = a1;
    register long _rsi asm("rsi") = a2;
    register long _rdx asm("rdx") = a3;
    asm volatile("syscall" : "+r"(_rax) : "r"(_rdi), "r"(_rsi), "r"(_rdx) : "rcx", "r11", "memory");
    return _rax;
}

[[gnu::always_inline]] static inline long __syscall_4(long id, long a1, long a2, long a3, long a4) {
    register long _rax asm("rax") = id;
    register long _rdi asm("rdi") = a1;
    register long _rsi asm("rsi") = a2;
    register long _rdx asm("rdx") = a3;
    register long _r10 asm("r10") = a4;
    asm volatile("syscall"
                 : "+r"(_rax)
                 : "r"(_rdi), "r"(_rsi), "r"(_rdx), "r"(_r10)
                 : "rcx", "r11", "memory");
    return _rax;
}

[[gnu::always_inline]] static inline long
__syscall_5(long id, long a1, long a2, long a3, long a4, long a5) {
    register long _rax asm("rax") = id;
    register long _rdi asm("rdi") = a1;
    register long _rsi asm("rsi") = a2;
    register long _rdx asm("rdx") = a3;
    register long _r10 asm("r10") = a4;
    register long _r8 asm("r8")   = a5;
    asm volatile("syscall"
                 : "+r"(_rax)
                 : "r"(_rdi), "r"(_rsi), "r"(_rdx), "r"(_r10), "r"(_r8)
                 : "rcx", "r11", "memory");
    return _rax;
}

[[gnu::always_inline]] static inline long
__syscall_6(long id, long a1, long a2, long a3, long a4, long a5, long a6) {
    register long _rax asm("rax") = id;
    register long _rdi asm("rdi") = a1;
    register long _rsi asm("rsi") = a2;
    register long _rdx asm("rdx") = a3;
    register long _r10 asm("r10") = a4;
    register long _r8 asm("r8")   = a5;
    register long _r9 asm("r9")   = a6;
    asm volatile("syscall"
                 : "+r"(_rax)
                 : "r"(_rdi), "r"(_rsi), "r"(_rdx), "r"(_r10), "r"(_r8), "r"(_r9)
                 : "rcx", "r11", "memory");
    return _rax;
}

#endif