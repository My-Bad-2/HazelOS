#include <stdio.h>
#include <string.h>

#include "api/ipc.h"
#include "api/syscalls.h"

static int ipc_test(void) {
    uint64_t chan_read, chan_write;
    uint64_t port_cap = 0;

    write(1, "Creating endpoints...\n", 23);

    if (ipc_channel_create(&chan_read, &chan_write) < 0) {
        write(1, "FAIL: Channel creation\n", 24);
        return 1;
    }

    if (ipc_port_create(&port_cap) < 0) {
        write(1, "FAIL: Port creation\n", 21);
        return 1;
    }

    write(1, "Binding port...\n", 17);

    int res = ipc_bind(port_cap, chan_read, 0xDEADBEEF);
    if (res < 0) {
        write(1, "FAIL: Port binding\n", 20);
        return 1;
    }

    write(1, "Cleaning up capabilities...\n", 29);

    if (ipc_close(chan_read) < 0 || ipc_close(chan_write) < 0 || ipc_close(port_cap) < 0) {
        write(1, "FAIL: Capability teardown\n", 27);
        return 1;
    }

    write(1, "Capabilities test passed!\n", 27);
    return 0;
}

// NOLINTNEXTLINE
void user_start() {
    const char* str = "Hello from Userspace!\n";
    size_t len      = strlen(str) + 1;

    ipc_test();

    write(1, str, len);

    uint64_t ret = fork();
    char buf[128];
    snprintf(buf, sizeof(buf), "Hello from Process (0x%lx)\n", ret);
    write(1, buf, sizeof(buf));

    while (true);
}