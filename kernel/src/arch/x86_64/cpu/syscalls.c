#include "core/syscalls.h"

#include <stdint.h>

#include "cpu/cpu.h"
#include "cpu/gdt.h"
#include "cpu/registers.h"
#include "cpu/syscalls.h"
#include "libs/log.h"
#include "sched/ipc.h"

// AMD64 Technology 24593—Rev. 3.42—March 2024 Pg. no. 175 System Instructions
#define STAR_SET_KERNEL_BASE(base) ((uint64_t)(base) << 32)
#define STAR_SET_USER_BASE(base)   ((uint64_t)(base) << 48)

#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))

typedef uint64_t (*syscall_handler_t)(struct interrupt_trapframe*);

struct syscall_category {
    const syscall_handler_t* handlers;
    size_t count;
};

static const syscall_handler_t ipc_syscalls[] = {
    [SYS_IPC_ENDPOINT_CREATE & 0xff] = sys_endpoint_create,
    [SYS_IPC_PORT_CREATE & 0xff]     = sys_port_create,
    [SYS_IPC_PORT_BIND & 0xff]       = sys_port_bind,
    [SYS_IPC_PORT_WAIT & 0xff]       = sys_port_wait,
    [SYS_IPC_CHANNEL_WRITE & 0xff]   = sys_channel_write,
    [SYS_IPC_CHANNEL_READ & 0xff]    = sys_channel_read,
    [SYS_IPC_CHANNEL_CALL & 0xff]    = sys_channel_call,
    [SYS_IPC_CHANNEL_FORWARD & 0xff] = sys_channel_forward,
};

static const syscall_handler_t cap_syscalls[] = {
    [SYS_CAP_DELEGATE & 0xff] = sys_cap_delegate,
    [SYS_CAP_CLOSE & 0xff]    = sys_cap_close,
    [SYS_CAP_COPY & 0xff]     = sys_cap_close,
    [SYS_CAP_MINT & 0xff]     = sys_cap_mint,
    [SYS_CAP_ALIAS & 0xff]    = sys_cap_alias,
};

static const syscall_handler_t sched_syscalls[] = {
    [SYS_SCHED_SPAWN_PROCESS & 0xff] = sys_process_create,
    [SYS_SCHED_SPAWN_THREAD & 0xff]  = sys_thread_spawn,
    [SYS_SCHED_CLONE & 0xff]         = sys_clone,
    [SYS_SCHED_YIELD & 0xff]         = sys_sched_yield,
    [SYS_SCHED_SLEEP & 0xff]         = sys_thread_sleep,
    [SYS_SCHED_PROCESS_EXIT & 0xff]  = sys_process_exit,
    [SYS_SCHED_THREAD_EXIT & 0xff]   = sys_thread_exit,
};

static const syscall_handler_t mem_syscalls[] = {
    [SYS_MEM_MAP & 0xff]     = sys_vspace_map,
    [SYS_MEM_UNMAP & 0xff]   = sys_vspace_unmap,
    [SYS_MEM_PROTECT & 0xff] = sys_vspace_protect,
    [SYS_VMO_CREATE & 0xff]  = sys_vmo_create,
    [SYS_VMO_RESIZE & 0xff]  = sys_vmo_resize,
    [SYS_VMO_READ & 0xff]    = sys_vmo_read,
    [SYS_VMO_WRITE & 0xff]   = sys_vmo_write,
    [SYS_VMO_CLONE & 0xff]   = sys_vmo_clone,
    [SYS_MEM_WPKRU & 0xff]   = sys_pkey_alloc,
};

static const syscall_handler_t timer_syscalls[] = {
    [SYS_TIMER_CREATE & 0xff] = sys_timer_create,
    [SYS_TIMER_CANCEL & 0xff] = sys_timer_cancel,
    [SYS_TIMER_SET & 0xff]    = sys_timer_set,
};

static const struct syscall_category dispatch_table[] = {
    [SYS_CATEGORY_CAP >> 8]   = {cap_syscalls, ARRAY_SIZE(cap_syscalls)},
    [SYS_CATEGORY_IPC >> 8]   = {ipc_syscalls, ARRAY_SIZE(ipc_syscalls)},
    [SYS_CATEGORY_SCHED >> 8] = {sched_syscalls, ARRAY_SIZE(sched_syscalls)},
    [SYS_CATEGORY_MEM >> 8]   = {mem_syscalls, ARRAY_SIZE(mem_syscalls)},
    [SYS_CATEGORY_TIMER >> 8] = {timer_syscalls, ARRAY_SIZE(timer_syscalls)},
};

// Forces the CPU to resolve the condition before speculatively loading from an array.
static inline uint64_t array_index(uint64_t index, uint64_t size) {
    uint64_t mask;

    // Generate a mask of all 1s if index < size, else all 0s.
    asm volatile("cmp %1, %2; sbb %0, %0;" : "=r"(mask) : "g"(size), "r"(index));
    return index & mask;
}

extern void syscall_entry(void);
extern void syscall_compat_entry(void);

void syscall_init(void) {
    if (!cpu_has_feature(FEATURE_SYSCALL)) PANIC("SYSCALL: CPU does not support SYSCALL/SYSRET.");

    uint64_t efer = read_msr(X86_MSR_IA32_EFER);
    if (!(efer & X86_EFER_SCE)) write_msr(X86_MSR_IA32_EFER, efer | X86_EFER_SCE);

    uint64_t star = STAR_SET_KERNEL_BASE(KERNEL_CODE);
    star |= STAR_SET_USER_BASE(USER_CODE32 | 3);
    write_msr(X86_MSR_IA32_STAR, star);

    write_msr(X86_MSR_IA32_LSTAR, (uint64_t)syscall_entry);
    write_msr(X86_MSR_IA32_CSTAR, (uint64_t)syscall_compat_entry);

    // Mask these flags upon syscall entry
    uint64_t mask = X86_FLAGS_IF | X86_FLAGS_DF | X86_FLAGS_TF | X86_FLAGS_CF | X86_FLAGS_PF |
                    X86_FLAGS_AF | X86_FLAGS_ZF | X86_FLAGS_SF | X86_FLAGS_OF;
    write_msr(X86_MSR_IA32_FMASK, mask);

    syscalls_init();
}

// NOLINTNEXTLINE
[[gnu::used, gnu::hot]] uint64_t syscall_dispatcher(struct interrupt_trapframe* regs) {
    uint64_t category_idx  = (regs->rax & 0xff00) >> 8;
    uint64_t operation_idx = (regs->rax & 0xff);

    if (unlikely(category_idx >= ARRAY_SIZE(dispatch_table)))
        return (regs->rax = (uint64_t)ERR_BAD_SYSCALL);

    // Speculative Execution Mitigation: Prevent out-of-bounds speculative array reads
    category_idx = array_index(category_idx, ARRAY_SIZE(dispatch_table));

    const struct syscall_category* cat = &dispatch_table[category_idx];

    if (unlikely(operation_idx >= cat->count || !cat->handlers[operation_idx])) {
        if (regs->rax == SYS_WRITE) {
            regs->rax = (uint64_t)sys_write((uint32_t)regs->rdi, (const char*)regs->rsi, regs->rdx);
            return regs->rax;
        }

        KLOG_DEBUG("Bad syscall invoked: 0x%lx\n", regs->rax);
        return (regs->rax = (uint64_t)ERR_BAD_SYSCALL);
    }

    operation_idx = array_index(operation_idx, cat->count);
    regs->rax     = cat->handlers[operation_idx](regs);
    return regs->rax;
}