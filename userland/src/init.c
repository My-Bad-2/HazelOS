#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "api/ipc.h"
#include "api/memory.h"
#include "api/syscalls.h"

#define MSG_SIZE   4096
#define TOTAL_MSGS 20

static uint64_t tx_ep = 0;

static void run_sender(void) {
    char payload[MSG_SIZE];
    memset(payload, 'X', MSG_SIZE);

    char buffer[128];

    snprintf(
        buffer,
        sizeof(buffer),
        "[Sender] Attempting to flood the channel with %d messages...\n",
        TOTAL_MSGS
    );
    write(1, buffer, sizeof(buffer));

    for (int i = 0; i < TOTAL_MSGS; ++i) {
        snprintf(buffer, sizeof(buffer), "[Sender] Queuing message %d...\n", i);
        write(1, buffer, sizeof(buffer));

        int ret = ipc_send(tx_ep, payload, MSG_SIZE, nullptr, 0, -1);

        if (ret == 0)
            snprintf(buffer, sizeof(buffer), "Success.\n");
        else
            snprintf(buffer, sizeof(buffer), "Failed! Error code: %d\n", ret);
        write(1, buffer, sizeof(buffer));
    }

    write(1, "[Sender] Finished sending all messages. Exiting.\n", 50);
    ipc_close(tx_ep);

    process_exit(0);
}

static void run_receiver(uint64_t rx_ep) {
    char buf[128];
    snprintf(
        buf,
        128,
        "[Receiver] Sleeping for 2 seconds to let the Sender hit the DoS quota...\n"
    );
    write(1, buf, 128);

    thread_sleep(2000000);

    snprintf(buf, 128, "\n[Receiver] Waking up! Draining the queue to relieve backpressure...\n");
    write(1, buf, 128);

    char buffer[MSG_SIZE];
    size_t actual_len;

    for (int i = 1; i <= TOTAL_MSGS; i++) {
        // Drain one message
        ipc_recv(rx_ep, buffer, MSG_SIZE, &actual_len, nullptr, 0, nullptr, nullptr, -1);
        snprintf(buf, 128, "[Receiver] Extracted message %d (%zu bytes)\n", i, actual_len);
        write(1, buf, 128);

        // Sleep for 100ms to watch the Sender stagger back to life
        thread_sleep(100000000);
    }

    snprintf(buf, 128, "[Receiver] Queue drained. Exiting.\n");
    write(1, buf, 128);
    ipc_close(rx_ep);
}

// NOLINTNEXTLINE
void user_start() {
    const char* str = "Hello from Userspace!\n";
    size_t len      = strlen(str) + 1;

    write(1, str, len);
    char buf[128];

    uint64_t vmo_cap;
    vmo_create(0x4000, VMO_CREATE_RAM, &vmo_cap);
    uintptr_t ptr = vspace_map(
        0,
        vmo_cap,
        0,
        0,
        0x4000,
        VSPACE_PROT_READ | VSPACE_PROT_WRITE | VSPACE_MAP_STACK
    );

    uint64_t ep_client, ep_server;
    int ret = ipc_channel_create(&ep_server, &ep_client);
    if (ret < 0) {
        snprintf(buf, sizeof(buf), "Failed to create channel!\n");
        write(1, buf, 128);
        while (true);
    }

    tx_ep = ep_server;

    clone(
        CLONE_VFORK | CLONE_COPY_CSPACE,
        (uintptr_t)ptr + 0x4000,
        (uintptr_t)run_sender,
        nullptr,
        nullptr,
        nullptr,
        nullptr
    );
    run_receiver(ep_client);

    while (true);
}