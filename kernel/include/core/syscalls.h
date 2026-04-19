#ifndef KERNEL_SCHED_SYSCALLS_H
#define KERNEL_SCHED_SYSCALLS_H 1

#include <stddef.h>
#include <stdint.h>

#include "cpu/syscalls.h"

#ifdef __cplusplus
extern "C" {
#endif

// Syscall Category
#define SYS_CATEGORY_CAP   0x0100
#define SYS_CATEGORY_IPC   0x0200
#define SYS_CATEGORY_SCHED 0x0300
#define SYS_CATEGORY_MEM   0x0400
#define SYS_CATEGORY_TIMER 0x0500

// Capability syscalls
#define SYS_CAP_DELEGATE (SYS_CATEGORY_CAP | 0x01)  // Grant a capability to another CNode
#define SYS_CAP_CLOSE    (SYS_CATEGORY_CAP | 0x02)  // Close a cap
#define SYS_CAP_COPY     (SYS_CATEGORY_CAP | 0x03)  // Duplicate a cap within the same CNode
#define SYS_CAP_MINT     (SYS_CATEGORY_CAP | 0x04)  // Copy a cap but downgrade its rights
#define SYS_CAP_ALIAS    (SYS_CATEGORY_CAP | 0x05)

// IPC syscalls
#define SYS_IPC_ENDPOINT_CREATE (SYS_CATEGORY_IPC | 0x01)
#define SYS_IPC_PORT_CREATE     (SYS_CATEGORY_IPC | 0x02)
#define SYS_IPC_PORT_BIND       (SYS_CATEGORY_IPC | 0x03)
#define SYS_IPC_PORT_WAIT       (SYS_CATEGORY_IPC | 0x04)
#define SYS_IPC_CHANNEL_WRITE   (SYS_CATEGORY_IPC | 0x05)
#define SYS_IPC_CHANNEL_READ    (SYS_CATEGORY_IPC | 0x06)
#define SYS_IPC_CHANNEL_CALL    (SYS_CATEGORY_IPC | 0x07)
#define SYS_IPC_CHANNEL_FORWARD (SYS_CATEGORY_IPC | 0x08)

// Scheduling/Thread/Process syscalls
#define SYS_SCHED_SPAWN_PROCESS (SYS_CATEGORY_SCHED | 0x01)
#define SYS_SCHED_SPAWN_THREAD  (SYS_CATEGORY_SCHED | 0x02)
#define SYS_SCHED_CLONE         (SYS_CATEGORY_SCHED | 0x03)
#define SYS_SCHED_YIELD         (SYS_CATEGORY_SCHED | 0x04)
#define SYS_SCHED_SLEEP         (SYS_CATEGORY_SCHED | 0x05)

// VSpace Syscalls
#define SYS_MEM_MAP     (SYS_CATEGORY_MEM | 0x01)
#define SYS_MEM_UNMAP   (SYS_CATEGORY_MEM | 0x02)
#define SYS_MEM_PROTECT (SYS_CATEGORY_MEM | 0x03)
#define SYS_VMO_CREATE  (SYS_CATEGORY_MEM | 0x04)
#define SYS_VMO_RESIZE  (SYS_CATEGORY_MEM | 0x05)
#define SYS_VMO_READ    (SYS_CATEGORY_MEM | 0x06)
#define SYS_VMO_WRITE   (SYS_CATEGORY_MEM | 0x07)
#define SYS_VMO_CLONE   (SYS_CATEGORY_MEM | 0x08)

// Timer Syscalls
#define SYS_TIMER_CREATE (SYS_CATEGORY_TIMER | 0x01)
#define SYS_TIMER_CANCEL (SYS_CATEGORY_TIMER | 0x02)
#define SYS_TIMER_SET    (SYS_CATEGORY_TIMER | 0x03)

#define SYS_WRITE 0x01
#define SYS_CLONE 0x38

#define STDOUT_FILENO 1
#define STDERR_FILENO 2

#define OPTION_WAIT_NOHANG 1

size_t copy_from_user(void* dest, const void* src, size_t len);
size_t copy_to_user(void* dest, const void* src, size_t len);

void syscalls_init(void);
int64_t sys_write(uint32_t fd, const char* user_buf, size_t count);

int64_t sys_fork(struct syscall_regs* tf);
void sys_exit(int exit_code);

// --- Scheduling Category ---
struct clone_args {
    uint64_t* out_proc_cap;
    uint64_t* out_cnode_cap;
    uint64_t* out_vspace_cap;
    uint64_t* out_thread_cap;
};

int64_t sys_process_create(
    const char* name,
    uint64_t* out_proc_cap,
    uint64_t* out_cnode_cap,
    uint64_t* out_vspace_cap
);

int64_t sys_thread_spawn(
    uint64_t target_proc_cap,
    uint64_t target_vspace_cap,
    uintptr_t entry_rip,
    uintptr_t stack_rsp,
    uint64_t arg1,
    uint64_t* out_thread_cap
);

int64_t sys_clone(
    uint64_t flags,
    uintptr_t child_rsp_override,
    uintptr_t child_rip_override,
    struct syscall_regs* regs,
    uint64_t* out_proc_cap,
    uint64_t* out_thread_cap,
    uint64_t* out_cnode_cap,
    uint64_t* out_vspace_cap
);

void sys_sched_yield(void);
int64_t sys_thread_sleep(uint64_t ns);

[[noreturn]] void thread_exit(int exit_code);
[[noreturn]] void thread_exit(int exit_code);

// Memory Management
#define VMO_CREATE_RAM       0x0001u  // Standard Zeroed RAM
#define VMO_CREATE_PHYSICAL  0x0002u  // Direct physical memory (MMIO)
#define VMO_CREATE_RESIZABLE 0x0004u

#define VSPACE_PROT_READ     0x0001u
#define VSPACE_PROT_WRITE    0x0002u
#define VSPACE_PROT_EXEC     0x0004u
#define VSPACE_MAP_EXACT     0x0100u   // Must map exactly at hint_addr or fail
#define VSPACE_MAP_OVERWRITE 0x0200u   // Map at hint_addr, destroying existing mappings
#define VSPACE_MAP_SHADOW    0x0400u   // Create a Copy-On-Write private clone of the VMO
#define VSPACE_MAP_STACK     0x0800u   // Allocates a guard page automatically at the bottom
#define VSPACE_MAP_LAZY      0x1000u   // Demand paging (allocate physical frames on fault)
#define VSPACE_MAP_WIRE      0x2000u   // Populate immediately AND lock into RAM (No eviction)
#define VSPACE_MAP_POPULATE  0x4000u   // Populate immediately, but allow future eviction
#define VSPACE_MAP_PAGE_2M   0x8000u   // Force 2MB Superpages
#define VSPACE_MAP_PAGE_1G   0x10000u  // Force 1GB Hugepages

int sys_vmo_create(size_t size, uint32_t vmo_flags, uint64_t* out_vmo_cap);
int sys_vmo_resize(uint64_t vmo_cap, size_t new_size);
int sys_vmo_read(uint64_t vmo_cap, void* buffer, size_t offset, size_t size);
int sys_vmo_write(uint64_t vmo_cap, const void* buffer, size_t offset, size_t size);
int sys_vmo_clone(
    uint64_t src_vmo_cap,
    size_t offset,
    size_t size,
    uint32_t flags,
    uint64_t* out_vmo_cap
);

uintptr_t sys_vspace_map(
    uint64_t vspace_cap,
    uint64_t vmo_cap,
    size_t vmo_offset,
    uintptr_t hint_addr,
    size_t size,
    uint32_t map_flags
);
int sys_vspace_unmap(uint64_t vspace_cap, uintptr_t addr, size_t size);
int sys_vspace_protect(uint64_t vspace_cap, uintptr_t addr, size_t size, uint32_t new_prots);

#ifdef __cplusplus
}
#endif

#endif