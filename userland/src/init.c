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

    uint64_t vmo_cap;
    vmo_create(0x3000, VMO_CREATE_RAM, &vmo_cap);
    uintptr_t ptr = vspace_map(
        0,
        vmo_cap,
        0,
        0,
        0x3000,
        VSPACE_PROT_READ | VSPACE_PROT_WRITE | VSPACE_MAP_LAZY
    );

    snprintf(buf, sizeof(buf), "ptr = %p\n", ptr);
    write(1, buf, sizeof(buf));
    *(uintptr_t*)ptr = 1000;
    snprintf(buf, sizeof(buf), "ptr = %lu\n", *(uintptr_t*)ptr);
    write(1, buf, sizeof(buf));

    while (true);
}