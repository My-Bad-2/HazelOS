#include <stdio.h>
#include <string.h>

#include "api/syscalls.h"

// NOLINTNEXTLINE
void user_start() {
    const char* str = "Hello from Userspace!\n";
    size_t len      = strlen(str) + 1;

    write(1, str, len);

    while (true);
}