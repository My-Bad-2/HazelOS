#include <stdarg.h>
#include <stdint.h>
#include <string.h>

#include "arch.h"
#include "compiler.h"
#include "core/capability.h"
#include "core/errors.h"
#include "cpu/smp.h"
#include "cpu/syscalls.h"
#include "libs/dlist.h"
#include "libs/handles.h"
#include "libs/kobject.h"
#include "libs/log.h"
#include "libs/rb_tree.h"
#include "libs/spinlock.h"
#include "memory/heap.h"
#include "memory/memory.h"
#include "memory/vm_object.h"
#include "memory/vma.h"
#include "sched/process.h"
#include "sched/sched_class.h"
#include "sched/scheduler.h"
#include "sched/semaphore.h"
#include "sched/wait.h"

static kmem_cache_t* thread_cache         = nullptr;
static struct dlist_head dead_thread_list = DLIST_INIT(dead_thread_list);
static qspinlock_t dead_thread_lock;

static struct semaphore reaper_sema;

static void process_insert_thread(process_t* p, thread_t* t) {
    dlist_add_tail(&t->process_node, &p->thread_list);
}

static thread_t* thread_create_internal(
    const char* name,
    process_t* proc,
    struct vm_space* vspace,
    uint8_t policy,
    uintptr_t entry_rip,
    uint64_t args,
    uintptr_t user_rsp,
    int* error_code,
    va_list arg
) {
    if (error_code) *error_code = ERR_OK;

    thread_t* curr      = smp_current_core()->curr_thread;
    struct cnode* croot = curr ? curr->owner->root_cnode : get_kernel_process()->root_cnode;

    if (unlikely(!proc || !vspace || proc->state != PROCESS_ALIVE)) {
        if (error_code) *error_code = ERR_SRCH;
        return nullptr;
    }

    // Ensure the VSpace capability actually matches the process we are injecting into
    if (unlikely(proc->vspace != vspace)) {
        if (error_code) *error_code = ERR_INVALID;
        return nullptr;
    }

    thread_t* t = kmem_cache_alloc(thread_cache);
    if (unlikely(!t)) {
        if (error_code) *error_code = ERR_NO_MEM;
        return nullptr;
    }

    memset(t, 0, sizeof(thread_t));
    kref_init(&t->kobj, CAP_TYPE_THREAD);

    t->owner        = proc;
    t->state        = THREAD_READY;
    t->assigned_cpu = UINT32_MAX;
    t->policy       = policy;

#if KERNEL_DEBUG
    if (likely(name)) strncpy(t->name, name, sizeof(t->name) - 1);
#endif

    rb_init_node(&t->rb_node);
    dlist_init(&t->run_node);

    dlist_init(&t->process_node);
    dlist_init(&t->wait_node);
    wait_queue_init(&t->join_queue);

    struct sched_class* sc = get_sched_class(policy);
    t->sched_class         = sc;
    if (sc->init_task) sc->init_task(t, arg);

    int ret = arch_thread_init(t, entry_rip, args, user_rsp);

    if (ret != ERR_OK) {
        kmem_cache_free(thread_cache, t);
        if (error_code) *error_code = ret;
        return nullptr;
    }

    acquire_qspinlock(&proc->lock);
    process_insert_thread(proc, t);
    proc->thread_count++;
    release_qspinlock(&proc->lock);

    return t;
}

thread_t* thread_create(
    const char* name,
    process_t* proc,
    struct vm_space* vspace,
    uint8_t policy,
    uintptr_t entry_rip,
    uint64_t args,
    uintptr_t user_rsp,
    int* error_code,
    ...
) {
    if (!thread_cache) {
        sema_init(&reaper_sema, 0);
        thread_cache = kmem_cache_create(
            "thread_cache",
            sizeof(thread_t),
            _Alignof(thread_t),
            SLAB_NEVER_MERGE | SLAB_HWCACHE_ALIGN,
            nullptr
        );
    }

    va_list arg;
    va_start(arg, error_code);
    thread_t* t = thread_create_internal(
        name,
        proc,
        vspace,
        policy,
        entry_rip,
        args,
        user_rsp,
        error_code,
        arg
    );

    va_end(arg);

    return t;
}

thread_t* thread_clone(
    process_t* target_proc,
    thread_t* parent,
    struct interrupt_trapframe* regs,
    uintptr_t rsp_override,
    uintptr_t rip_override,
    int* error_code
) {
    if (error_code) *error_code = ERR_OK;
    if (unlikely(!target_proc || !parent || !regs)) {
        if (error_code) *error_code = ERR_INVALID;
        return nullptr;
    }

    thread_t* child = kmem_cache_alloc(thread_cache);
    if (unlikely(!child)) {
        if (error_code) *error_code = ERR_NO_MEM;
        return nullptr;
    }

    memset(child, 0, sizeof(thread_t));

    kref_init(&child->kobj, CAP_TYPE_THREAD);
    child->owner         = target_proc;
    child->assigned_cpu  = UINT32_MAX;
    child->state         = THREAD_READY;
    child->policy        = parent->policy;
    child->sched_class   = parent->sched_class;
    child->affinity_mask = parent->affinity_mask;

#if KERNEL_DEBUG
    if (likely(parent->name)) strncpy(child->name, parent->name, 31);
#endif

    rb_init_node(&child->rb_node);
    dlist_init(&child->run_node);
    dlist_init(&child->process_node);
    dlist_init(&child->wait_node);
    wait_queue_init(&child->join_queue);
    memcpy(&child->sched, &parent->sched, sizeof(sched_entity_t));

    vm_object_t* vmo = vm_object_create(VM_OBJ_ANONYMOUS, KSTACK_SIZE);

    child->kernel_stack = vmalloc(
        kernel_space,
        nullptr,
        KSTACK_SIZE,
        VMM_FLAG_STACK | VMM_FLAG_WRITE | VMM_FLAG_READ,
        CACHE_WRITE_BACK,
        PAGE_SIZE_SMALL,
        vmo,
        0
    );

    vm_object_deref(vmo);

    if (unlikely(!child->kernel_stack)) {
        kmem_cache_free(thread_cache, child);
        if (error_code) *error_code = ERR_NO_MEM;
        return nullptr;
    }

    child->kernel_stack_top = (uintptr_t)child->kernel_stack + KSTACK_SIZE;

    int error = arch_thread_clone(child, parent, regs, rsp_override, rip_override);
    if (error != ERR_OK && error != ERR_CHILD) {
        vmfree(kernel_space, child->kernel_stack, KSTACK_SIZE);
        kmem_cache_free(thread_cache, child);
        if (error_code) *error_code = error;
        return nullptr;
    }

    acquire_qspinlock(&target_proc->lock);
    process_insert_thread(target_proc, child);
    target_proc->thread_count++;
    release_qspinlock(&target_proc->lock);

    return child;
}

void thread_exit(int exit_code) {
    arch_disable_interrupts();
    per_cpu_data_t* cpu = smp_current_core();
    thread_t* curr      = cpu->curr_thread;

    curr->exit_code = exit_code;
    wait_queue_wake_up_all(&curr->join_queue);

    bool is_last_thread = false;
    if (curr->owner) {
        acquire_qspinlock(&curr->owner->lock);
        if (curr->owner->thread_count <= 1) is_last_thread = true;
        release_qspinlock(&curr->owner->lock);
    }

    if (is_last_thread && curr->owner->state == PROCESS_ALIVE) process_exit(exit_code);

    curr->state = THREAD_TERMINATED;
    scheduler_remove_thread(curr);

    acquire_qspinlock(&dead_thread_lock);
    dlist_add_tail(&curr->wait_node, &dead_thread_list);
    release_qspinlock(&dead_thread_lock);

    sema_up(&reaper_sema);
    scheduler_yield();
    PANIC("THREAD: Escaped the afterlife");
}

void thread_join(thread_t* t, int* exit_code) {
    if (unlikely(!t)) return;

    wait_event(&t->join_queue, t->state == THREAD_TERMINATED);
    if (exit_code) *exit_code = t->exit_code;
    kref_put(&t->kobj, thread_release);
}

void thread_release(struct kobject* obj) {
    if (unlikely(!obj)) return;

    thread_t* t = kref_entry(obj, struct thread, kobj);
    arch_thread_destroy(t);
    kmem_cache_free(thread_cache, t);
}

void reaper_task_entry(void*) {
    KLOG_INFO("REAPER: background cleanup thread started\n");

    while (true) {
        sema_down(&reaper_sema);

        acquire_qspinlock(&dead_thread_lock);

        if (dlist_empty(&dead_thread_list)) {
            release_qspinlock(&dead_thread_lock);
            continue;
        }

        struct dlist_head* node = dead_thread_list.next;
        dlist_del(node);
        release_qspinlock(&dead_thread_lock);

        thread_t* dead_thread = dlist_entry(node, thread_t, wait_node);
        kref_put(&dead_thread->kobj, thread_release);
    }
}

void thread_wait(thread_t* t, int* exit_code) {
    if (unlikely(!t)) return;

    wait_event(&t->join_queue, t->state == THREAD_TERMINATED);

    acquire_qspinlock(&t->lock);
    if (exit_code) *exit_code = t->exit_code;
    t->state = THREAD_TERMINATED;
    release_qspinlock(&t->lock);
}