#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "api/memory.h"
#include "api/syscalls.h"

// NOLINTNEXTLINE
void user_start() {
    const char* str = "Hello from Userspace!\n";
    size_t len      = strlen(str) + 1;

    write(1, str, len);

    char buf[128];
    void* ptr = mmap(nullptr, 0x1000, PROT_READ | PROT_WRITE, MAP_PRIVATE, 0, 0);
    snprintf(buf, sizeof(buf), "mmap test = %p\n", ptr);
    munmmap(ptr, 0x1000);
    write(1, buf, sizeof(buf));

    while (true);
}