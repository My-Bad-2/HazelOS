#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "compiler.h"
#include "cpu/exception.h"
#include "cpu/gdt.h"
#include "cpu/registers.h"
#include "cpu/simd.h"
#include "cpu/smp.h"
#include "cpu/syscalls.h"
#include "libs/log.h"
#include "libs/math.h"
#include "libs/spinlock.h"
#include "memory/heap.h"
#include "memory/memory.h"
#include "memory/pagemap.h"
#include "memory/vma.h"
#include "sched/process.h"

extern void kernel_thread_entry(void);
extern void isr_restore_path(void);
extern void syscall_restore_path(void);

static kmem_cache_t* fpu_cache = nullptr;
static qspinlock_t fpu_cache_init_lock;

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

struct fork_stack_layout {
    switch_context_t ctx;
    struct syscall_regs regs;
    uint64_t thread_exit;
};

static inline void ensure_fpu_cache_initialized(void) {
    if (unlikely(!fpu_cache)) {
        size_t flags = acquire_qinterrupt_lock(&fpu_cache_init_lock);

        if (!fpu_cache) {
            size_t fpu_size = simd_get_save_size();
            fpu_cache       = kmem_cache_create("fpu_cache", fpu_size, 64, 0, nullptr);
        }

        release_qinterrupt_lock(&fpu_cache_init_lock, flags);
    }
}

bool arch_thread_init(thread_t* t, void (*entry)(void*), void* arg) {
    if (unlikely(!t || !entry)) return false;

    ensure_fpu_cache_initialized();

    t->fpu_buffer = kmem_cache_alloc(fpu_cache);
    if (unlikely(!t->fpu_buffer)) return false;

    t->kernel_stack = vmalloc(
        kernel_space,
        nullptr,
        KSTACK_SIZE,
        VMM_FLAG_STACK | VMM_FLAG_WRITE | VMM_FLAG_READ,
        CACHE_WRITE_BACK,
        PAGE_SIZE_SMALL
    );
    if (unlikely(!t->kernel_stack)) {
        kmem_cache_free(fpu_cache, t->fpu_buffer);
        return false;
    }

    const size_t fpu_size = simd_get_save_size();
    memcpy(t->fpu_buffer, simd_get_clean_state(), fpu_size);

    t->kernel_stack_top = (uintptr_t)t->kernel_stack + KSTACK_SIZE;
    uintptr_t sp        = align_down(t->kernel_stack_top, 0x10);

    process_t* proc = t->owner;
    if (proc->is_kernel) {
        sp -= sizeof(uint64_t);
        *((uint64_t*)sp) = (uint64_t)thread_exit;

        sp -= sizeof(struct kernel_stack_layout);
        struct kernel_stack_layout* kstack = (struct kernel_stack_layout*)sp;
        memset(kstack, 0, sizeof(struct kernel_stack_layout));

        kstack->entry   = (uint64_t)entry;
        kstack->args    = (uint64_t)arg;
        kstack->ctx.rip = (uint64_t)kernel_thread_entry;

        t->context_rsp = (uint64_t)&kstack->ctx;
    } else {
        t->user_stack = (void*)vmalloc(
            &proc->space,
            nullptr,
            USTACK_SIZE,
            VMM_FLAG_READ | VMM_FLAG_WRITE | VMM_FLAG_USER | VMM_FLAG_STACK,
            CACHE_WRITE_BACK,
            PAGE_SIZE_SMALL
        );

        if (unlikely(!t->user_stack)) {
            vmfree(kernel_space, t->kernel_stack, KSTACK_SIZE);
            kmem_cache_free(fpu_cache, t->fpu_buffer);
            return false;
        }

        sp -= sizeof(struct user_stack_layout);
        struct user_stack_layout* ustack = (struct user_stack_layout*)sp;
        memset(ustack, 0, sizeof(struct user_stack_layout));

        uint64_t rsp = align_down((uintptr_t)t->user_stack + USTACK_SIZE, 0x10);

        ustack->tf.rip    = (uint64_t)entry;
        ustack->tf.rdi    = (uint64_t)arg;
        ustack->tf.cs     = USER_CODE | 3;
        ustack->tf.ss     = USER_DATA | 3;
        ustack->tf.rflags = X86_FLAGS_IF | X86_FLAGS_RESERVED_ONES;
        ustack->tf.rsp    = rsp;
        ustack->ctx.rip   = (uint64_t)isr_restore_path;

        t->context_rsp = (uint64_t)&ustack->ctx;
    }

    return true;
}

void arch_thread_destroy(thread_t* t) {
    if (unlikely(!t)) return;

    if (t->kernel_stack) vmfree(kernel_space, t->kernel_stack, KSTACK_SIZE);
    if (t->fpu_buffer) kmem_cache_free(fpu_cache, t->fpu_buffer);

    if (likely(!t->owner->is_kernel && t->context_rsp != 0 && t->user_stack))
        vmfree(&t->owner->space, t->user_stack, USTACK_SIZE);
}

void arch_thread_clone(thread_t* child, struct syscall_regs* tf, void* child_stack) {
    if (unlikely(!child || !tf)) return;

    ensure_fpu_cache_initialized();
    child->fpu_buffer = kmem_cache_alloc(fpu_cache);
    if (unlikely(!child->fpu_buffer)) PANIC("THREAD: fpu buffer allocation failed\n");

    thread_t* parent = smp_current_core()->curr_thread;
    thread_save_fpu(parent);

    size_t fpu_size = simd_get_save_size();
    memcpy(child->fpu_buffer, parent->fpu_buffer, fpu_size);

    uintptr_t sp = align_down(child->kernel_stack_top, 0x10);
    sp -= sizeof(struct fork_stack_layout);

    struct fork_stack_layout* layout = (struct fork_stack_layout*)sp;
    memset(layout, 0, sizeof(struct fork_stack_layout));

    layout->regs     = *tf;
    layout->regs.rax = 0;

    if (child_stack) layout->regs.rsp = (uintptr_t)child_stack;
    layout->ctx.rip    = (uint64_t)syscall_restore_path;
    child->context_rsp = (uint64_t)&layout->ctx;
}

void thread_save_fpu(thread_t* t) {
    if (likely(t && t->fpu_buffer)) simd_save(t->fpu_buffer);
}

void thread_restore_fpu(thread_t* t) {
    if (likely(t && t->fpu_buffer)) simd_restore(t->fpu_buffer);
}

int thread_change_exec(
    thread_t* t,
    vm_space_t* new_space,
    uintptr_t entry_point,
    uintptr_t new_rsp,
    struct syscall_regs* regs
) {
    if (unlikely(!t || !t->owner || !regs)) return -EINVAL;

    process_t* proc      = t->owner;
    vm_space_t old_space = proc->space;

    acquire_qspinlock(&proc->lock);
    proc->space = *new_space;
    proc->map   = *new_space->map;
    release_qspinlock(&proc->lock);

    pagemap_load(&proc->map);
    vmm_destroy_space(&old_space);

    memset(regs, 0, sizeof(struct syscall_regs));
    regs->rip    = entry_point;
    regs->rsp    = new_rsp;
    regs->rflags = X86_FLAGS_IF | X86_FLAGS_RESERVED_ONES;

    wait_queue_wake_up_all(&proc->vfork_wait_queue);
    return 0;
}