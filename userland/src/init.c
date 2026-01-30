#include <string.h>

#include "api/syscalls.h"

void user_start() {
    const char* str = "Hello from Userspace!\n";
    size_t len      = strlen(str);

    write(1, str, len);

halt:
    while (true);
}