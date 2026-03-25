#ifndef USERLAND_SYSCALLS_H
#define USERLAND_SYSCALLS_H 1

#include <stddef.h>
#include <stdint.h>

#include "ipc.h"

#ifdef __cplusplus
extern "C" {
#endif

#define SYS_CATEGORY_CAP 0x0100
#define SYS_CATEGORY_IPC 0x0200

#define SYS_CAP_RETYPE   (SYS_CATEGORY_CAP | 0x01)  // Carve objects from untyped memory
#define SYS_CAP_DELEGATE (SYS_CATEGORY_CAP | 0x02)  // Grant a capability to another CNode
#define SYS_CAP_REVOKE   (SYS_CATEGORY_CAP | 0x03)  // Recursively destroy derived caps
#define SYS_CAP_COPY     (SYS_CATEGORY_CAP | 0x04)  // Duplicate a cap within the same CNode
#define SYS_CAP_MINT     (SYS_CATEGORY_CAP | 0x05)  // Copy a cap but downgrade its rights

#define SYS_IPC_CHANNEL_CREATE (SYS_CATEGORY_IPC | 0x01)
#define SYS_IPC_PORT_CREATE    (SYS_CATEGORY_IPC | 0x02)
#define SYS_IPC_BIND           (SYS_CATEGORY_IPC | 0x03)
#define SYS_IPC_CALL           (SYS_CATEGORY_IPC | 0x04)
#define SYS_IPC_WAIT           (SYS_CATEGORY_IPC | 0x05)
#define SYS_IPC_CLOSE          (SYS_CATEGORY_IPC | 0x06)
#define SYS_IPC_SEND           (SYS_CATEGORY_IPC | 0x07)
#define SYS_IPC_RECV           (SYS_CATEGORY_IPC | 0x08)

#define SYS_WRITE    0x01
#define SYS_MMAP     0x09
#define SYS_MPROTECT 0x0a
#define SYS_MUNMAP   0x0b
#define SYS_MREMAP   0x19
#define SYS_CLONE    0x38
#define SYS_FORK     0x39
#define SYS_VFORK    0x3a
#define SYS_EXIT     0x3c

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

#ifdef __cplusplus
}
#endif

#endif