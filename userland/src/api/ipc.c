#include "api/ipc.h"

#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "api/capability.h"
#include "syscall.h"

#ifdef __x86_64__
static inline long syscall_ipc_recv_fast(uint64_t chan, uint64_t mr[4], uint32_t* badge_out) {
    long ret;

    register long rdx asm("rdx");
    register long r10 asm("r10");
    register long r8 asm("r8");
    register long r9 asm("r9");
    register long r12 asm("r12");

    asm volatile("syscall"
                 : "=a"(ret), "=d"(rdx), "=r"(r10), "=r"(r8), "=r"(r9)
                 : "a"(SYS_IPC_RECV), "D"((long)chan), "S"(0)
                 : "rcx", "r11", "memory");

    mr[0] = (uint64_t)r10;
    mr[1] = (uint64_t)r8;
    mr[2] = (uint64_t)r9;
    mr[3] = (uint64_t)r12;

    if (badge_out) {
        *badge_out = rdx;
    }

    return ret;
}

static inline long syscall_ipc_call_fast(
    uint64_t chan,
    const uint64_t tx_mr[4],
    uint64_t rx_mr[4],
    uint32_t* badge_out
) {
    long ret;

    register long rdi asm("rdi") = (long)chan;
    register long r10 asm("r10") = (long)tx_mr[0];
    register long r8 asm("r8")   = (long)tx_mr[1];
    register long r9 asm("r9")   = (long)tx_mr[2];
    register long r12 asm("r12") = (long)tx_mr[3];

    asm volatile("syscall"
                 : "=a"(ret), "+D"(rdi), "+r"(r10), "+r"(r8), "+r"(r9), "+r"(r12)
                 : "a"(SYS_IPC_CALL), "d"(0), "S"(0)
                 : "rcx", "r11", "memory");

    rx_mr[0] = (uint64_t)r10;
    rx_mr[1] = (uint64_t)r8;
    rx_mr[2] = (uint64_t)r9;
    rx_mr[3] = (uint64_t)r12;

    if (badge_out) {
        *badge_out = (uint64_t)rdi;
    }

    return ret;
}

#endif

int ipc_channel_create(uint64_t* cap1_out, uint64_t* cap2_out) {
    uint64_t caps[2] = {0, 0};
    int ret          = (int)syscall(SYS_IPC_CHANNEL_CREATE, (long)caps);

    if (ret == 0) {
        if (cap1_out) {
            *cap1_out = caps[0];
        }

        if (cap2_out) {
            *cap2_out = caps[1];
        }
    }

    return ret;
}

int ipc_port_create(uint64_t* port_cap_out) {
    return (int)syscall(SYS_IPC_PORT_CREATE, (long)port_cap_out);
}

int ipc_close(uint64_t cap_id) {
    return cap_close(cap_id);
}

int ipc_notification_create(uint64_t* cap_id_out) {
    uint64_t cap = 0;
    int ret      = (int)syscall(SYS_IPC_NOTIFICATION_CREATE, (long)cap);

    if (ret == 0 && cap_id_out) {
        *cap_id_out = cap;
    }

    return ret;
}

int ipc_notify(uint64_t notif_cap_id, uint64_t bits) {
    return (int)syscall(SYS_IPC_NOTIFY, (long)notif_cap_id, (long)bits);
}

int ipc_bind(uint64_t port_cap, uint64_t chan_cap, uint64_t key) {
    return (int)syscall(SYS_IPC_BIND, (long)port_cap, (long)chan_cap, (long)key);
}

int ipc_wait(uint64_t port_cap, struct ipc_event* out_event, int timeout_ms) {
    return (int)syscall(SYS_IPC_WAIT, (long)port_cap, (long)out_event, (long)timeout_ms);
}

int ipc_send(
    uint64_t chan_cap,
    const void* data,
    size_t len,
    const uint64_t* caps,
    size_t num_caps,
    int timeout_ms
) {
    if (len <= 32 && num_caps == 0) {
        uint64_t mr[4] = {0};

        if (len > 0) {
            memcpy(mr, data, len);
        }

        return (int)syscall(
            SYS_IPC_SEND,
            (long)chan_cap,
            0,
            (long)mr[0],
            (long)mr[1],
            (long)mr[2],
            (long)mr[3]
        );
    }
    struct ipc_msg_info info = {
        .data_buffer      = (void*)data,
        .data_size_max    = len,
        .data_size_actual = 0,
        .caps_buffer      = (uint64_t*)caps,
        .caps_max         = num_caps,
        .caps_actual      = 0
    };

    return (int)syscall(SYS_IPC_SEND, (long)chan_cap, (long)&info, (long)timeout_ms);
}

int ipc_recv(
    uint64_t chan_cap,
    void* buffer,
    size_t max_len,
    size_t* actual_len,
    uint64_t* cap_buffer,
    size_t max_caps,
    size_t* actual_caps,
    uint32_t* badge_out,
    int timeout_ms
) {
    if (max_len <= 32 && max_caps == 0) {
        uint64_t mr[4] = {0};
        int ret        = (int)syscall_ipc_recv_fast(chan_cap, mr, badge_out);

        if (ret == 0 && max_len > 0) {
            memcpy(buffer, mr, max_len);

            if (actual_len) {
                *actual_len = max_len;
            }

            if (actual_caps) {
                *actual_caps = 0;
            }
        }

        return ret;
    }

    struct ipc_msg_info info = {
        .data_buffer      = buffer,
        .data_size_max    = max_len,
        .data_size_actual = 0,
        .caps_buffer      = cap_buffer,
        .caps_max         = max_caps,
        .caps_actual      = 0
    };

    int ret = (int)syscall(SYS_IPC_RECV, (long)chan_cap, (long)&info, (long)timeout_ms);

    if (actual_len) {
        *actual_len = info.data_size_actual;
    }

    if (actual_caps) {
        *actual_caps = info.caps_actual;
    }

    return ret;
}

int ipc_call(
    uint64_t chan_cap,
    const void* req_data,
    size_t req_len,
    const uint64_t* req_caps,
    size_t req_num_caps,
    void* resp_buffer,
    size_t resp_max_len,
    size_t* resp_actual_len,
    uint64_t* resp_cap_buffer,
    size_t resp_max_caps,
    size_t* resp_actual_caps,
    uint32_t* badge_out,
    int timeout_ms
) {
    if (req_len <= 32 && req_num_caps == 0 && resp_max_len <= 32 && resp_max_caps == 0) {
        uint64_t tx_mr[4] = {0};
        uint64_t rx_mr[4] = {0};

        if (req_len > 0) memcpy(tx_mr, req_data, req_len);

        int ret = (int)syscall_ipc_call_fast(chan_cap, tx_mr, rx_mr, badge_out);

        if (ret == 0 && resp_max_len > 0) {
            memcpy(resp_buffer, rx_mr, resp_max_len);

            if (resp_actual_len) {
                *resp_actual_len = resp_max_len;
            }

            if (resp_actual_caps) {
                *resp_actual_caps = 0;
            }
        }

        return ret;
    }
    struct ipc_msg_info tx_info = {
        .data_buffer      = (void*)req_data,
        .data_size_max    = req_len,
        .data_size_actual = 0,
        .caps_buffer      = (uint64_t*)req_caps,
        .caps_max         = req_num_caps,
        .caps_actual      = 0
    };

    struct ipc_msg_info rx_info = {
        .data_buffer      = resp_buffer,
        .data_size_max    = resp_max_len,
        .data_size_actual = 0,
        .caps_buffer      = resp_cap_buffer,
        .caps_max         = resp_max_caps,
        .caps_actual      = 0
    };

    int ret = (int)
        syscall(SYS_IPC_CALL, (long)chan_cap, (long)&tx_info, (long)&rx_info, (long)timeout_ms);

    if (resp_actual_len) {
        *resp_actual_len = rx_info.data_size_actual;
    }

    if (resp_actual_caps) {
        *resp_actual_caps = rx_info.caps_actual;
    }

    return ret;
}

int ipc_send_msg(
    uint64_t chan_cap,
    const void* data,
    size_t len,
    const uint64_t* caps,
    size_t cap_count
) {
    return ipc_send(chan_cap, data, len, caps, cap_count, 10);
}

int ipc_recv_msg(
    uint64_t chan_cap,
    uint64_t port_cap,
    void* buffer,
    size_t max_len,
    uint64_t* caps_out,
    size_t max_caps,
    size_t* recv_len,
    size_t* recv_caps
) {
    if (port_cap > 0) {
        struct ipc_event event;
        int wait_ret = ipc_wait(port_cap, &event, -1);

        if (wait_ret < 0) {
            return wait_ret;
        }
    }

    uint32_t badge_out;

    int ret = ipc_recv(
        chan_cap,
        buffer,
        max_len,
        recv_len,
        caps_out,
        max_caps,
        recv_caps,
        &badge_out,
        10
    );
    return ret;
}