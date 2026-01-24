#include <string.h>

#include "api/syscalls.h"

void user_start() {
    const char* str = "Hello from Userspace!\n";
    size_t len      = strlen(str);

    int32_t handles[2]  = {};
    uintptr_t ring_addr = 0;

    write(1, str, len);
    int ret = ipc_create_channel(handles, &ring_addr);

    while (true);
}