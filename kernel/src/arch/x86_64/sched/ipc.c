#include "sched/ipc.h"

#include "cpu/syscalls.h"

void arch_sys_ipc_send(struct syscall_regs* regs, struct thread_ipc_state* state) {
    state->msg_regs[0] = regs->r10;
    state->msg_regs[1] = regs->r8;
    state->msg_regs[2] = regs->r9;
    state->msg_regs[3] = regs->r12;
}

void arch_sys_ipc_recv(struct syscall_regs* regs, struct thread_ipc_state* state) {
    regs->r10 = state->msg_regs[0];
    regs->r8  = state->msg_regs[1];
    regs->r9  = state->msg_regs[2];
    regs->r12 = state->msg_regs[3];

    regs->rdi = state->sender_badge;
}