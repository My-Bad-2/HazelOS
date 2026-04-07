#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "api/memory.h"
#include "api/syscalls.h"

static void test(void) {
    write(1, "Hello from cloned thread!\n", 25);

    while (true);
}

// NOLINTNEXTLINE
void user_start() {
    const char* str = "Hello from Userspace!\n";
    size_t len      = strlen(str) + 1;

    write(1, str, len);

    void* ptr = mmap(nullptr, 0x4000, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_GROWSDOWN, 0, 0);

    uint64_t t_cap;
    int64_t ret =
        clone(0, (uintptr_t)ptr + 0x4000, (uintptr_t)test, nullptr, &t_cap, nullptr, nullptr);

    char buf[128];
    snprintf(buf, sizeof(buf), "Hello from original thread\n");
    write(1, buf, sizeof(buf));

    while (true);
}