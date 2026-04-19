#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "compiler.h"
#include "core/errors.h"
#include "cpu/exception.h"
#include "cpu/gdt.h"
#include "cpu/registers.h"
#include "cpu/simd.h"
#include "cpu/syscalls.h"
#include "libs/log.h"
#include "libs/math.h"
#include "libs/spinlock.h"
#include "memory/heap.h"
#include "memory/memory.h"
#include "memory/pagemap.h"
#include "memory/pmm.h"
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

struct clone_stack_layout {
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

int arch_thread_init(thread_t* t, uintptr_t entry_rip, uint64_t arg1, uintptr_t user_rsp) {
    if (unlikely(!t || !entry_rip)) return ERR_INVALID;

    ensure_fpu_cache_initialized();

    t->fpu_buffer = kmem_cache_alloc(fpu_cache);
    if (unlikely(!t->fpu_buffer)) return ERR_NO_MEM;

    t->kernel_stack = (void*)to_higher_half((uintptr_t)pmm_alloc(KSTACK_SIZE / PAGE_SIZE_SMALL));

    if (unlikely(!t->kernel_stack)) {
        kmem_cache_free(fpu_cache, t->fpu_buffer);
        return ERR_NO_MEM;
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

        kstack->entry   = entry_rip;
        kstack->args    = arg1;
        kstack->ctx.rip = (uint64_t)kernel_thread_entry;

        t->context_rsp = (uint64_t)&kstack->ctx;
    } else {
        sp -= sizeof(struct user_stack_layout);
        struct user_stack_layout* ustack = (struct user_stack_layout*)sp;
        memset(ustack, 0, sizeof(struct user_stack_layout));

        ustack->tf.rip    = entry_rip;
        ustack->tf.rdi    = arg1;
        ustack->tf.cs     = USER_CODE | 3;
        ustack->tf.ss     = USER_DATA | 3;
        ustack->tf.rflags = X86_FLAGS_IF | X86_FLAGS_RESERVED_ONES;
        ustack->tf.rsp    = user_rsp;
        ustack->ctx.rip   = (uint64_t)isr_restore_path;

        t->context_rsp = (uint64_t)&ustack->ctx;
    }

    return ERR_OK;
}

void arch_thread_destroy(thread_t* t) {
    if (unlikely(!t)) return;

    if (t->kernel_stack) vmfree(kernel_space, t->kernel_stack, KSTACK_SIZE);
    if (t->fpu_buffer) kmem_cache_free(fpu_cache, t->fpu_buffer);
}

int arch_thread_clone(
    thread_t* child,
    thread_t* parent,
    struct syscall_regs* tf,
    uintptr_t rsp_override,
    uintptr_t rip_override
) {
    if (unlikely(!child || !tf)) return ERR_INVALID;

    ensure_fpu_cache_initialized();
    child->fpu_buffer = kmem_cache_alloc(fpu_cache);
    if (unlikely(!child->fpu_buffer)) return ERR_NO_MEM;

    thread_save_fpu(parent);

    size_t fpu_size = simd_get_save_size();
    memcpy(child->fpu_buffer, parent->fpu_buffer, fpu_size);

    uintptr_t sp = align_down(child->kernel_stack_top, 0x10);
    sp -= sizeof(struct clone_stack_layout);

    struct clone_stack_layout* layout = (struct clone_stack_layout*)sp;
    memset(layout, 0, sizeof(struct clone_stack_layout));

    layout->regs     = *tf;
    layout->regs.rax = 0;

    if (rsp_override) layout->regs.rsp = rsp_override;
    if (rip_override) layout->regs.rip = rip_override;

    layout->ctx.rip    = (uint64_t)syscall_restore_path;
    child->context_rsp = (uint64_t)&layout->ctx;
    return ERR_OK;
}

void thread_save_fpu(thread_t* t) {
    if (likely(t && t->fpu_buffer)) simd_save(t->fpu_buffer);
}

void thread_restore_fpu(thread_t* t) {
    if (likely(t && t->fpu_buffer)) simd_restore(t->fpu_buffer);
}