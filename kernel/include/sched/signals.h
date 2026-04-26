#ifndef KERNEL_SCHED_SIGNAL_H
#define KERNEL_SCHED_SIGNAL_H 1

#include <stdint.h>

#include "cpu/syscalls.h"

#define SIGHUP  0x01
#define SIGINT  0x02
#define SIGQUIT 0x03
#define SIGILL  0x04
#define SIGFPE  0x08
#define SIGKILL 0x09
#define SIGSEGV 0x0b
#define SIGTERM 0x0f
#define SIGCONT 0x12
#define SIGSTOP 0x13

#define NSIG 64

#define SIG_DFL ((void (*)(int))0)
#define SIG_IGN ((void (*)(int))1)

typedef uint64_t sigset_t;

struct sigaction {
    void (*sa_handler)(int);

    sigset_t sa_mask;
    int sa_flags;
};

struct sigframe {
    sigset_t old_mask;
    struct interrupt_trapframe regs;
    void* fpu_state;
};

#endif