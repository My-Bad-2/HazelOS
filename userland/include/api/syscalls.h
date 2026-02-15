#ifndef USERLAND_SYSCALLS_H
#define USERLAND_SYSCALLS_H 1

#include <stddef.h>
#include <stdint.h>

#include "ipc.h"

#ifdef __cplusplus
extern "C" {
#endif

#define SYS_WRITE    1
#define SYS_MMAP     9
#define SYS_MPROTECT 10
#define SYS_MUNMAP   11
#define SYS_EXIT     60

// Custom syscalls
#define SYS_IPC_CREATE_CHANNEL  500
#define SYS_IPC_CREATE_PORT_SET 501
#define SYS_IPC_BIND            502
#define SYS_IPC_NOTIFY          503
#define SYS_IPC_WAIT            504
#define SYS_HANDLE_CLOSE        505
#define SYS_IPC_SEND_HANDLES    506
#define SYS_IPC_RECV_HANDLES    507
#define SYS_IPC_TIMER_ARM       508
#define SYS_IPC_SHM_ALLOC       509

#define MAP_HUGE_SHIFT 26
#define MAP_HUGE_MASK  0x3f

#define PROT_NONE  0
#define PROT_EXEC  0x01
#define PROT_READ  0x02
#define PROT_WRITE 0x04

#define MAP_SHARED    0x01
#define MAP_PRIVATE   0x02
#define MAP_ANONYMOUS 0x04
#define MAP_FIXED     0x08
#define MAP_GROWSDOWN 0x10
#define MAP_HUGETLB   0x20
#define MAP_POPULATE  0x40
#define MAP_STACK     0x80

#define MAP_HUGE_2MB (21 << MAP_HUGE_SHIFT)
#define MAP_HUGE_1GB (30 << MAP_HUGE_SHIFT)

typedef long off_t;

int64_t write(int fd, const char* str, size_t len);
void* mmap(void* addr, size_t length, int prot, int flags, int fd, off_t offset);
int munmmap(void* addr, size_t length);
int mprotect(void* addr, size_t length, int prot);

int ipc_create_channel(int32_t* handles, uintptr_t* out);
int ipc_create_port_set(void);

int ipc_bind(int32_t port_set, int32_t channel, uint64_t key);
int ipc_notify(int32_t channel);
int ipc_wait(int32_t port_set, ipc_event_t* event, int timeout_ms);
int ipc_handle_close(int32_t handle);

int ipc_send_handles(int32_t handle, int32_t* handles, size_t n);
int ipc_recv_handles(int32_t handle, int32_t* handles, size_t max_count);

int ipc_timer_arm_oneshot(
    int32_t port_handle,
    uint64_t user_key,
    uint64_t deadline_ms,
    int32_t* handle_out
);
int ipc_timer_arm_periodic(
    int32_t port_handle,
    uint64_t user_key,
    uint64_t deadline_ms,
    int32_t* handle_out
);
int ipc_shm_alloc(size_t size, int flags, int32_t* handle_out, uintptr_t* vaddr_out);

#ifdef __cplusplus
}
#endif

#endif