#include <string.h>

#include "api/syscalls.h"

void user_start() {
    const char* str = "Hello from Userspace!\n";
    size_t len      = strlen(str);

    write(1, str, len);

    int32_t h_port = ipc_create_port_set();

    if (h_port < 0) {
        write(1, "Failed to create Port Set\n", 27);
        goto halt;
    }

    int32_t h_timer;
    int ret = ipc_timer_arm_oneshot(h_port, 0xCAFEBABE, 1, &h_timer);

    if (ret < 0) {
        write(1, "Failed to arm timer!\n", 22);
        goto halt;
    }

halt:
    while (true);
}