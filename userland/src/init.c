#include <stdio.h>
#include <string.h>

#include "api/ipc.h"
#include "api/syscalls.h"

static int ipc_test() {
    int32_t handles[2];

    int ret = ipc_create_channel(handles);

    if (ret < 0) {
        write(1, "Failed to create channel!\n", 28);
        return 1;
    }

    int32_t h_read  = handles[0];
    int32_t h_write = handles[1];

    int32_t port_handle;
    ret = ipc_create_port_set(&port_handle);
    if (ret < 0) {
        write(1, "Failed to create port set!\n", 27);
        return 1;
    }

    ipc_bind(port_handle, h_read, 0x1234);

    const char* msg     = "Aye-Aye, Captain!\n";
    int32_t send_handle = h_write;

    write(1, "Writing to channel...\n", 23);

    ret = ipc_send_msg(h_write, msg, strlen(msg) + 1, &send_handle, 1);

    if (ret < 0) {
        write(1, "FAIL: Send message\n", 21);
        return 1;
    }

    char buf[128];
    int32_t recv_handles[4];
    uint32_t len     = 0;
    uint32_t h_count = 0;

    write(1, "Reading from channel...\n", 25);

    ret = ipc_recv_msg(h_read, port_handle, buf, sizeof(buf), recv_handles, 4, &len, &h_count);
    if (ret < 0) {
        write(1, "FAIL: Recv Message\n", 21);
        return 1;
    }

    write(1, "Recieved payload: \n", 20);
    write(1, buf, 128);
    return 0;
}

// NOLINTNEXTLINE
void user_start() {
    const char* str = "Hello from Userspace!\n";
    size_t len      = strlen(str) + 1;

    ipc_test();
    write(1, str, len);

    int ret = fork();
    char buf[128];
    snprintf(buf, 128, "Hello from PID %d\n", ret);
    write(1, buf, 128);

    while (true);
}