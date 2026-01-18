#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "arch.h"
#include "cpu/exception.h"
#include "cpu/gdt.h"
#include "cpu/registers.h"
#include "cpu/simd.h"
#include "cpu/smp.h"
#include "libs/log.h"
#include "libs/math.h"
#include "memory/heap.h"
#include "memory/memory.h"
#include "memory/pagemap.h"
#include "memory/vma.h"
#include "sched/process.h"
#include "sched/scheduler.h"

extern void kernel_thread_entry(void);
extern void isr_restore_path(void);

struct kernel_stack_layout {
    switch_context_t ctx;
    uint64_t args;
    uint64_t entry;
};

struct user_stack_layout {
    switch_context_t ctx;
    interrupt_trapframe_t tf;
    uint64_t thread_exit;
};

// NOLINTNEXTLINE(misc-use-internal-linkage)
[[noreturn, gnu::used]] void thread_exit(void) {
    arch_disable_interrupts();
    thread_t* curr = smp_current_core()->curr_thread;
    scheduler_remove_thread(curr);
    scheduler_yield();

    PANIC("THREAD: terminated thread called from the afterlife");
}

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
        KLOG_WARN("THREAD: kernel stack allocation failed tid=%u\n", t->tid);
        return false;
    }

    size_t fpu_size = simd_get_save_size();
    t->fpu_buffer   = kmalloc(fpu_size);

    if (!t->fpu_buffer) {
        vmm_free(&kernel_space, t->kernel_stack, KSTACK_SIZE);
        errno = ENOMEM;
        PANIC("THREAD: fpu buffer allocation failed tid=%u pid=%u\n", t->tid, proc->pid);
        return false;
    }

    void* clean_state = simd_get_clean_state();

    if (!clean_state) {
        errno = ENODEV;
        KLOG_ERROR("THREAD: missing SIMD clean state tid=%u pid=%u\n", t->tid, proc->pid);
        kfree(t->fpu_buffer, fpu_size);
        vmm_free(&kernel_space, t->kernel_stack, KSTACK_SIZE);
        return false;
    }

    memcpy(t->fpu_buffer, clean_state, fpu_size);

    t->kernel_stack_top = (uintptr_t)t->kernel_stack + KSTACK_SIZE;
    uintptr_t sp        = align_down(t->kernel_stack_top, 0x10);

    if (proc->is_kernel) {
        sp -= sizeof(struct kernel_stack_layout);

        struct kernel_stack_layout* kstack = (struct kernel_stack_layout*)sp;
        memset(kstack, 0, sizeof(struct kernel_stack_layout));

        kstack->entry   = (uint64_t)entry;
        kstack->args    = (uint64_t)arg;
        kstack->ctx.rip = (uint64_t)kernel_thread_entry;

        t->context_rsp = (uint64_t)&kstack->ctx;
    } else {
        sp -= sizeof(struct user_stack_layout);
        struct user_stack_layout* ustack = (struct user_stack_layout*)sp;
        memset(ustack, 0, sizeof(struct user_stack_layout));

        uint32_t flags = VMM_FLAG_READ | VMM_FLAG_WRITE | VMM_FLAG_USER | VMM_FLAG_STACK;

        size_t size       = USTACK_SIZE;
        void* ustack_base = vmm_alloc(&proc->space, size, flags, CACHE_WRITE_BACK, PAGE_SIZE_SMALL);

        if (!ustack_base) {
            vmm_free(&proc->space, t->kernel_stack, KSTACK_SIZE);
            errno = ENOMEM;
            KLOG_WARN("THREAD: user stack allocation failed tid=%u pid=%u\n", t->tid, proc->pid);
            return false;
        }

        t->user_stack = ustack_base;
        uint64_t rsp  = (uintptr_t)ustack_base + USTACK_SIZE;
        rsp           = align_down(rsp, 0x10);

        ustack->tf.rip = (uint64_t)entry;
        ustack->tf.rdi = (uint64_t)arg;

        ustack->tf.cs = USER_CODE | 3;
        ustack->tf.ss = USER_DATA | 3;

        ustack->tf.rflags = X86_FLAGS_IF | X86_FLAGS_RESERVED_ONES;
        ustack->tf.rsp    = rsp;

        ustack->ctx.rip = (uint64_t)isr_restore_path;
        t->context_rsp  = (uint64_t)&ustack->ctx;
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

    if (t->fpu_buffer) {
        size_t fpu_size = simd_get_save_size();
        kfree(t->fpu_buffer, fpu_size);
    }

    if (!t->owner->is_kernel && t->context_rsp != 0) {
        vmm_free(&proc->space, t->user_stack, USTACK_SIZE);
    }
}

void arch_thread_clone(thread_t* child, interrupt_trapframe_t* tf) {
    if (!child || !tf) {
        errno = EINVAL;
        KLOG_WARN("THREAD: clone called with null args child=%p tf=%p\n", child, tf);
        return;
    }

    size_t fpu_size   = simd_get_save_size();
    child->fpu_buffer = kmalloc(fpu_size);

    if (!child->fpu_buffer) {
        vmm_free(&kernel_space, child->kernel_stack, KSTACK_SIZE);
        errno = ENOMEM;
        PANIC(
            "THREAD: fpu buffer allocation failed tid=%u pid=%u\n",
            child->tid,
            child->owner->pid
        );
        return;
    }

    void* clean_state = simd_get_clean_state();
    memcpy(child->fpu_buffer, clean_state, fpu_size);

    uintptr_t sp = align_down(child->kernel_stack_top, 0x10);

    sp -= sizeof(struct user_stack_layout);
    struct user_stack_layout* layout = (struct user_stack_layout*)sp;

    memset(layout, 0, sizeof(struct user_stack_layout));

    layout->tf     = *tf;
    layout->tf.rax = 0;

    layout->ctx.rip    = (uint64_t)isr_restore_path;
    child->context_rsp = (uint64_t)&layout->tf;
}

void thread_save_fpu(thread_t* t) {
    if (!t) {
        errno = EINVAL;
        KLOG_WARN("THREAD: save_fpu called with null thread\n");
        return;
    }

    if (t->fpu_buffer) {
        simd_save(t->fpu_buffer);
    }
}

void thread_restore_fpu(thread_t* t) {
    if (!t) {
        errno = EINVAL;
        KLOG_WARN("THREAD: restore_fpu called with null thread\n");
        return;
    }

    if (t->fpu_buffer) {
        simd_restore(t->fpu_buffer);
    }
}