#include <stdio.h>
#include <string.h>

#include "api/ipc.h"
#include "api/syscalls.h"

static int ipc_test() {
    int32_t handles[2];
    uintptr_t ring_vaddr = 0;

    int ret = ipc_create_channel(handles, &ring_vaddr);

    if (ret < 0) {
        write(1, "Failed to create channel!\n", 28);
        return 1;
    }

    int32_t h_read   = handles[0];
    int32_t h_write  = handles[1];
    ipc_ring_t* ring = (ipc_ring_t*)ring_vaddr;

    ring->head = 0;
    ring->tail = 0;

    int32_t port_set = ipc_create_port_set();
    if (port_set < 0) {
        write(1, "Failed to create port set!\n", 27);
        return 1;
    }

    ipc_bind(port_set, h_read, 0x1234);

    const char* msg     = "Not sure what I did, but hey, if it works, it works.\n";
    int32_t send_handle = h_write;

    write(1, "Writing to ring...\n", 21);

    ret = ipc_send_msg(h_write, ring, msg, strlen(msg) + 1, &send_handle, 1);

    if (ret < 0) {
        write(1, "FAIL: Send message\n", 21);
        return 1;
    }

    char buf[128];
    int32_t recv_handles[4];
    uint32_t len     = 0;
    uint32_t h_count = 0;

    write(1, "Reading from ring...\n", 23);

    ret = ipc_recv_msg(h_read, port_set, ring, buf, 128, recv_handles, 4, &len, &h_count);

    if (ret < 0) {
        write(1, "FAIL: Recv Message\n", 21);
        return 1;
    }

    write(1, buf, 128);
    return 0;
}

void user_start() {
    const char* str = "Hello from Userspace!\n";
    size_t len      = strlen(str) + 1;

    ipc_test();

    write(1, str, len);

    while (true);
}