#include <stdint.h>

static inline int64_t syscall1(uint64_t syscall_number, uint64_t arg1) {
    int64_t ret;
    asm volatile (
        "syscall"
        : "=a" (ret)          // Output: RAX -> ret
        : "a" (syscall_number), // Input: syscall_number -> RAX
          "D" (arg1)          // Input: arg1 -> RDI
        : "rcx", "r11", "memory" // Clobbers: RCX, R11 destroyed by sysret
    );
    return ret;
}

extern "C" void user_start() {
    // const char* hello = "Hello from userland!";
    // syscall1(0, reinterpret_cast<uintptr_t>(hello));

    while (true) {
    }
}