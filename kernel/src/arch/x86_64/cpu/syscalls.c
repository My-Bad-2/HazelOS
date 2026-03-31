#include "cpu/syscalls.h"

#include <stdint.h>

#include "compiler.h"
#include "core/capability.h"
#include "core/errors.h"
#include "cpu/cpu.h"
#include "cpu/gdt.h"
#include "cpu/registers.h"
#include "cpu/smp.h"
#include "libs/log.h"
#include "memory/vma.h"
#include "sched/ipc.h"
#include "sched/process.h"
#include "sched/syscalls.h"
#include "uapi/ipc.h"

// AMD64 Technology 24593—Rev. 3.42—March 2024 Pg. no. 175 System Instructions
#define STAR_SET_KERNEL_BASE(base) ((uint64_t)(base) << 32)
#define STAR_SET_USER_BASE(base)   ((uint64_t)(base) << 48)

extern void syscall_entry(void);
extern void syscall_compat_entry(void);

void syscall_init(void) {
    if (!cpu_has_feature(FEATURE_SYSCALL)) {
        PANIC("SYSCALL: CPU does not support SYSCALL/SYSRET.");
    }

    uint64_t efer = read_msr(X86_MSR_IA32_EFER);

    if (!(efer & X86_EFER_SCE)) {
        write_msr(X86_MSR_IA32_EFER, efer | X86_EFER_SCE);
    }

    uint64_t star = STAR_SET_KERNEL_BASE(KERNEL_CODE);
    star |= STAR_SET_USER_BASE(USER_CODE32 | 3);

    write_msr(X86_MSR_IA32_STAR, star);

    // LSTAR: The 64-bit entry point for syscalls
    write_msr(X86_MSR_IA32_LSTAR, (uint64_t)syscall_entry);
    // CSTAR: The 32-bit entry point for syscalls
    write_msr(X86_MSR_IA32_CSTAR, (uint64_t)syscall_compat_entry);

    uint64_t mask = X86_FLAGS_IF | X86_FLAGS_DF | X86_FLAGS_TF | X86_FLAGS_CF | X86_FLAGS_PF |
                    X86_FLAGS_AF | X86_FLAGS_ZF | X86_FLAGS_SF | X86_FLAGS_OF;

    write_msr(X86_MSR_IA32_FMASK, mask);

    syscalls_init();
}

typedef uint64_t (*syscall_fn_t)(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);

static uint64_t
dispatch_cap_syscall(uint64_t operation, per_cpu_data_t* cpu, struct syscall_regs* regs) {
    struct cnode* root_cnode = cpu->curr_thread->owner->root_cnode;

    if (unlikely(!root_cnode)) {
        return (uint64_t)ERR_DENIED;
    }

    int status          = ERR_DENIED;
    uint64_t out_cap_id = 0;

    switch (operation) {
        case 0x01:  // SYS_CAP_DELEGATE
        {
            status = sys_cap_delegate(root_cnode, regs->rdi, regs->rsi, regs->rdx, &out_cap_id);

            if (status == ERR_OK) {
                regs->rdx = out_cap_id;
            }

            break;
        }
        case 0x02:  // SYS_CAP_CLOSE
        {
            status = sys_cap_close(root_cnode, regs->rdi);
            break;
        }
        case 0x03:  // SYS_CAP_COPY
        {
            status = sys_cap_copy(root_cnode, regs->rdi, regs->rsi, &out_cap_id);

            if (status == ERR_OK) {
                regs->rdx = out_cap_id;
            }

            break;
        }
        case 0x04:  // SYS_CAP_MINT
        {
            status =
                sys_cap_mint(root_cnode, regs->rdi, regs->rsi, regs->rdx, regs->r10, &out_cap_id);

            if (status == ERR_OK) {
                regs->rdx = out_cap_id;
            }

            break;
        }
        case 0x05:  // SYS_CAP_ALIAS
        {
            status = sys_cap_alias(root_cnode, regs->rdi, regs->rsi, &out_cap_id);
            if (status == ERR_OK) {
                regs->rdx = out_cap_id;
            }

            break;
        }
        default:
            status = ERR_DENIED;
            break;
    }

    return (uint64_t)status;
}

static uint64_t dispatch_ipc_syscall(uint64_t operation, struct syscall_regs* regs) {
    int status = 0;

    switch (operation) {
        case 0x01:  // SYS_IPC_CHANNEL_CREATE
            status = sys_ipc_create_channel((uint64_t*)regs->rdi);
            break;
        case 0x02:  // SYS_IPC_PORT_CREATE
            status = sys_ipc_port_create((uint64_t*)regs->rdi);
            break;
        case 0x03:  // SYS_IPC_BIND
            status = sys_ipc_bind(regs->rdi, regs->rsi, regs->rdx);
            break;
        case 0x04:  // SYS_IPC_CALL
            status = sys_ipc_call(
                regs->rdi,
                (struct ipc_msg_info*)regs->rsi,
                (struct ipc_msg_info*)regs->rdx,
                (int)regs->rdx,
                regs
            );
            break;
        case 0x05:  // SYS_IPC_WAIT
            status = sys_ipc_wait(regs->rdi, (struct ipc_event*)regs->rsi, (int)regs->rdx);
            break;
        case 0x06:  // SYS_IPC_SEND
            status = sys_ipc_send(regs->rdi, (struct ipc_msg_info*)regs->rsi, (int)regs->rdx, regs);
            break;
        case 0x07:  // SYS_IPC_RECV
            status = sys_ipc_recv(regs->rdi, (struct ipc_msg_info*)regs->rsi, (int)regs->rdx, regs);
            break;
        case 0x08:  // SYS_IPC_NOTIFICATION_CREATE
            status = sys_ipc_notification_create((uint64_t*)regs->rdi);
            break;
        case 0x09:  // SYS_IPC_NOTIFY
            status = sys_ipc_notify(regs->rdi, regs->rsi);
            break;
        default:
            status = ERR_DENIED;
            break;
    }

    return (uint64_t)status;
}

static uint64_t
dispatch_sched_syscall(uint64_t operation, struct syscall_regs* regs, struct process*) {
    uint64_t res = 0;

    switch (operation) {
        case 0x01:  // SYS_SCHED_FORK
            res = sys_fork(regs);
            break;
        default:
            res = (uint64_t)ERR_DENIED;
            break;
    }

    return res;
}

static uint64_t dispatch_misc_syscall(struct syscall_regs* regs, struct process* proc) {
    uint64_t res = 0;
    switch (regs->rax) {
        case SYS_WRITE:
            // RDI = FD; RSI = Buffer Pointer; RDX = count
            res = (uint64_t)sys_write((uint32_t)regs->rdi, (void*)regs->rsi, regs->rdx);
            break;
        // case SYS_MMAP:
        //     res = (uint64_t)sys_mmap(
        //         proc->space,
        //         (void*)regs->rdi,
        //         regs->rsi,
        //         (int)regs->rdx,
        //         (int)regs->r10,
        //         (int)regs->r8,
        //         (long)regs->r9
        //     );
        //     break;
        // case SYS_MPROTECT:
        //     res = (uint64_t)sys_mprotect(proc->space, (void*)regs->rdi, regs->rsi,
        //     (int)regs->rdx); break;
        // case SYS_MUNMAP:
        //     res = (uint64_t)sys_munmap(proc->space, (void*)regs->rdi, regs->rsi);
        //     break;
        // case SYS_MREMAP:
        //     res = (uint64_t)sys_mremap(
        //         proc->space,
        //         (void*)regs->rdi,
        //         regs->rsi,
        //         regs->rdx,
        //         (int)regs->r10,
        //         (void*)regs->r8
        //     );
        //     break;
        case SYS_EXIT:
            sys_exit((int)regs->rdi);
            res = regs->rdi;
            break;
        default:
            KLOG_DEBUG("Syscall %lu called!\n", regs->rax);
            break;
    }

    return res;
}

// NOLINTNEXTLINE(misc-use-internal-linkage)
uint64_t syscall_dispatcher(struct syscall_regs* regs) {
    uint64_t res = 0;

    uint64_t sys_num   = regs->rax;
    uint64_t category  = sys_num & 0xff00;
    uint64_t operation = sys_num & 0x00ff;

    per_cpu_data_t* cpu = smp_current_core();
    process_t* proc     = cpu->curr_thread->owner;

    switch (category) {
        case SYS_CATEGORY_CAP:
            res = dispatch_cap_syscall(operation, cpu, regs);
            break;
        case SYS_CATEGORY_IPC:
            res = dispatch_ipc_syscall(operation, regs);
            break;
        case SYS_CATEGORY_SCHED:
            res = dispatch_sched_syscall(operation, regs, proc);
            break;
        default:
            res = dispatch_misc_syscall(regs, proc);
            break;
    }

    regs->rax = res;

    return res;
}