#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "api/ipc.h"
#include "api/memory.h"
#include "api/syscalls.h"
#include "api/timer.h"

static uint64_t server_ep = 0;
static uint64_t client_ep = 0;

static void run_proc1(void) {
    write(1, "[Process - 1] Starting up...\n", 30);

    uint64_t port_cap;
    ipc_port_create(&port_cap);

    ipc_bind(port_cap, server_ep, 0x100);

    struct port_event event;
    write(1, "[Process - 1] Entering event loop...\n", 38);

    if (ipc_wait(port_cap, &event, -1) == 0) {
        if (event.signals & IPC_SIGNAL_READABLE) {
            char buffer[64]   = {0};
            size_t bytes_read = 0;

            ipc_recv(
                server_ep,
                buffer,
                sizeof(buffer),
                &bytes_read,
                nullptr,
                0,
                nullptr,
                nullptr,
                -1
            );

            char buf[128];

            snprintf(buf, sizeof(buf), "[Process - 1] Received: '%s'\n", buffer);
            write(1, buf, sizeof(buf));

            const char* reply = "PONG from Process - 1!";
            write(1, "[Process - 1] Sending reply...\n", 32);
            ipc_send(server_ep, reply, strlen(reply) + 1, nullptr, 0);
        }
    }

    ipc_close(port_cap);
    ipc_close(server_ep);
    write(1, "[Process - 1] Shutting down.\n", 30);

    while (true);
}

static void run_proc2() {
    write(1, "[Process - 2] Starting up...\n", 30);

    const char* msg = "PING from Process - 2!";
    write(1, "[Process - 2] Sending message...\n", 34);

    ipc_send(client_ep, msg, strlen(msg) + 1, nullptr, 0);

    char buffer[64]   = {0};
    size_t bytes_read = 0;

    write(1, "[Process - 2] Waiting for reply...\n", 36);

    ipc_recv(client_ep, buffer, sizeof(buffer), &bytes_read, nullptr, 0, nullptr, nullptr, -1);

    char buf[128];
    snprintf(buf, sizeof(buf), "[Process - 2] Received Reply: '%s'\n", buffer);
    write(1, buf, sizeof(buf));

    ipc_close(client_ep);
    write(1, "[Process - 2] Shutting down.\n", 30);

    while (true);
}

// NOLINTNEXTLINE
void user_start() {
    const char* str = "Hello from Userspace!\n";
    size_t len      = strlen(str) + 1;

    // uint64_t periodic_timer_cap;
    // uint64_t port_cap;
    // uint64_t oneshot_timer_cap;
    // timer_create(&periodic_timer_cap);
    // timer_create(&oneshot_timer_cap);

    write(1, str, len);

    // if (ipc_port_create(&port_cap) != 0) write(1, "Failed to create port!\n", 24);

    // ipc_bind(port_cap, periodic_timer_cap, 0x200);
    // ipc_bind(port_cap, oneshot_timer_cap, 0x100);

    // timer_set_periodic(periodic_timer_cap, 50000);
    // timer_set_oneshot(oneshot_timer_cap, 2000 * (NS_PER_SEC / MS_PER_SEC));

    // uint64_t ticks    = 0;
    // bool running = true;
    // struct port_event event;

    // char buf[128];

    // while (running) {
    //     if (ipc_wait(port_cap, &event, -1) == 0) {
    //         if (event.signals & IPC_SIGNAL_READABLE) {
    //             if(event.key == 0x200) ticks++;

    //             if(event.key == 0x100) {
    //                 running = false;
    //             }
    //         }
    //     }
    // }

    // snprintf(buf, sizeof(buf), "Total periodic timer ticks = 0x%lx\n", ticks);
    // write(1, buf, sizeof(buf));

    // timer_cancel(periodic_timer_cap);

    // ipc_close(periodic_timer_cap);
    // ipc_close(oneshot_timer_cap);
    // ipc_close(port_cap);

    // if (ipc_channel_create(&server_ep, &client_ep) < 0) write(1, "Failed to create channel!\n",
    // 27);

    // void* ptr  = mmap(nullptr, 0x4000, PROT_READ | PROT_WRITE, MAP_GROWSDOWN | MAP_PRIVATE, 0,
    // 0); void* ptr2 = mmap(nullptr, 0x4000, PROT_READ | PROT_WRITE, MAP_GROWSDOWN | MAP_PRIVATE,
    // 0, 0);

    // clone(
    //     CLONE_COPY_CSPACE,
    //     (uintptr_t)ptr + 0x4000,
    //     (uintptr_t)run_proc1,
    //     nullptr,
    //     nullptr,
    //     nullptr,
    //     nullptr
    // );

    // clone(
    //     CLONE_COPY_CSPACE,
    //     (uintptr_t)ptr2 + 0x4000,
    //     (uintptr_t)run_proc2,
    //     nullptr,
    //     nullptr,
    //     nullptr,
    //     nullptr
    // );

    while (true);
}