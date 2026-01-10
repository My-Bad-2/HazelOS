#include <errno.h>
#include <stddef.h>
#include <stdint.h>

#include "cpu/gdt.h"
#include "cpu/registers.h"
#include "libs/log.h"
#include "libs/math.h"
#include "memory/memory.h"
#include "memory/pagemap.h"
#include "memory/vma.h"
#include "sched/process.h"

bool arch_thread_init(thread_t* t, void (*entry)(void*), void* arg) {
    if (!t) {
        errno = EINVAL;
        KLOG_WARN("THREAD: init called with null thread\n");
        return false;
    }

    process_t* proc = t->owner;

    t->kernel_stack = vmm_alloc(
        &kernel_space,
        KSTACK_SIZE,
        VMM_FLAG_STACK | VMM_FLAG_WRITE | VMM_FLAG_READ,
        CACHE_WRITE_BACK,
        PAGE_SIZE_SMALL
    );

    if (!t->kernel_stack) {
        errno = ENOMEM;
        KLOG_WARN("THREAD: kernel stack allocation failed tid=%d\n", t->tid);
        return false;
    }

    t->kernel_stack_top = (uintptr_t)t->kernel_stack + KSTACK_SIZE;

    t->context.rip    = (uint64_t)entry;
    t->context.rdi    = (uint64_t)arg;
    t->context.rflags = X86_FLAGS_IF;

    if (proc->is_kernel) {
        t->context.cs = offsetof(gdt_table_t, entries) + (1 * sizeof(gdt_entry_t));
        t->context.ss = offsetof(gdt_table_t, entries) + (2 * sizeof(gdt_entry_t));

        // Kernel threads run on the kernel stack
        t->context.rsp = t->kernel_stack_top;
    } else {
        t->context.cs = offsetof(gdt_table_t, entries) + (4 * sizeof(gdt_entry_t));
        t->context.ss = offsetof(gdt_table_t, entries) + (3 * sizeof(gdt_entry_t));

        uint32_t flags = VMM_FLAG_READ | VMM_FLAG_WRITE | VMM_FLAG_USER | VMM_FLAG_STACK;

        size_t size  = USTACK_SIZE;
        void* ustack = vmm_alloc(&proc->space, size, flags, CACHE_WRITE_BACK, PAGE_SIZE_SMALL);

        if (!ustack) {
            vmm_free(&proc->space, t->kernel_stack, KSTACK_SIZE);
            errno = ENOMEM;
            KLOG_WARN("THREAD: user stack allocation failed tid=%d pid=%d\n", t->tid, proc->pid);
            return false;
        }

        t->user_stack = ustack;
        uint64_t rsp  = (uintptr_t)ustack + USTACK_SIZE;
        rsp           = align_down(rsp, 0x10);

        t->context.rsp = rsp;
    }

    return true;
}

void arch_thread_destroy(thread_t* t) {
    if (!t) {
        return;
    }

    process_t* proc = t->owner;

    if (t->kernel_stack) {
        vmm_free(&kernel_space, t->kernel_stack, KSTACK_SIZE);
    }

    if (!t->owner->is_kernel && t->context.rsp != 0) {
        vmm_free(&proc->space, t->user_stack, USTACK_SIZE);
    }
}