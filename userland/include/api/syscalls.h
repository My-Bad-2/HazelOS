#ifndef USERLAND_SYSCALLS_H
#define USERLAND_SYSCALLS_H 1

#include <stddef.h>
#include <stdint.h>

#include "ipc.h"

#ifdef __cplusplus
extern "C" {
#endif

#define SYS_WRITE    0x01
#define SYS_MMAP     0x09
#define SYS_MPROTECT 0x0a
#define SYS_MUNMAP   0x0b
#define SYS_MREMAP   0x19
#define SYS_CLONE    0x38
#define SYS_FORK     0x39
#define SYS_VFORK    0x3a
#define SYS_EXIT     0x3c

// Custom syscalls
#define SYS_IPC_CREATE_CHANNEL  500
#define SYS_IPC_CREATE_PORT_SET 501
#define SYS_IPC_BIND            502
#define SYS_IPC_NOTIFY          503
#define SYS_IPC_WAIT            504
#define SYS_HANDLE_CLOSE        505
#define SYS_IPC_SEND_MSG        506
#define SYS_IPC_RECV_MSG        507
#define SYS_IPC_TIMER_ARM       508
#define SYS_IPC_SHM_ALLOC       509

#define MAP_HUGE_SHIFT 26
#define MAP_HUGE_MASK  0x3f

#define PROT_NONE  0
#define PROT_EXEC  0x01
#define PROT_READ  0x02
#define PROT_WRITE 0x04

#define MAP_SHARED          0x001
#define MAP_PRIVATE         0x002
#define MAP_ANONYMOUS       0x004
#define MAP_FIXED_NOREPLACE 0x008
#define MAP_FIXED           0x010
#define MAP_GROWSDOWN       0x020
#define MAP_HUGETLB         0x040
#define MAP_POPULATE        0x080
#define MAP_STACK           0x100
#define MAP_LOCKED          0x200

#define MAP_HUGE_2MB (21 << MAP_HUGE_SHIFT)
#define MAP_HUGE_1GB (30 << MAP_HUGE_SHIFT)

#define MREMAP_MAYMOVE   0x01
#define MREMAP_FIXED     0x02
#define MREMAP_DONTUNMAP 0x04

typedef long off_t;

int64_t write(int fd, const char* str, size_t len);
void* mmap(void* addr, size_t length, int prot, int flags, int fd, off_t offset);
int munmmap(void* addr, size_t length);
int mprotect(void* addr, size_t length, int prot);
void* sys_mremap(void* old_address, size_t old_size, size_t new_size, int flags, void* new_address);
int fork(void);

int ipc_create_channel(int32_t* handles);
int ipc_create_port_set(int32_t* handle);

int ipc_bind(int32_t port_set, int32_t channel, uint64_t key);
int ipc_notify(int32_t channel);
int ipc_wait(int32_t port_set, ipc_event_t* event, int timeout_ms);
int ipc_handle_close(int32_t handle);

int sys_ipc_send_msg(
    int32_t chan_handle,
    const void* user_data,
    size_t size,
    int32_t* user_handles,
    size_t num_handles
);
int sys_ipc_recv_msg(int32_t chan_handle, ipc_msg_info_t* info);
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