#include <stdarg.h>
#include <stdint.h>
#include <string.h>

#include "arch.h"
#include "cpu/exception.h"
#include "libs/dlist.h"
#include "libs/handles.h"
#include "libs/log.h"
#include "libs/rb_tree.h"
#include "libs/spinlock.h"
#include "memory/heap.h"
#include "memory/memory.h"
#include "sched/process.h"
#include "sched/sched_class.h"
#include "sched/scheduler.h"

static kmem_cache_t* thread_cache         = nullptr;
static struct dlist_head dead_thread_list = DLIST_INIT(dead_thread_list);
static spinlock_t dead_thread_lock;

static struct dlist_head reaper_wait_queue = DLIST_INIT(reaper_wait_queue);

static void wake_up_all(struct dlist_head* queue) {
    struct thread* curr = nullptr;

    dlist_for_each_entry(curr, queue, wait_node) {
        dlist_del(&curr->wait_node);

        scheduler_unblock(curr);
    }
}

static void sleep_on_queue(struct dlist_head* queue) {
    thread_t* curr = smp_current_core()->curr_thread;
    dlist_add_tail(&curr->wait_node, queue);
    scheduler_block();
}

static void process_insert_thread(process_t* p, thread_t* t) {
    if (!p || !t) {
        return;
    }

    dlist_add_tail(&t->process_node, &p->thread_list);
}

static thread_t* thread_create_internal(
    const char* name,
    process_t* proc,
    uint8_t policy,
    void (*entry)(void*),
    void* args,
    va_list arg
) {
    if (!entry || !proc) {
        return nullptr;
    }

    thread_t* t = kmem_cache_alloc(thread_cache);
    if (!t) {
        return nullptr;
    }

    memset(t, 0, sizeof(thread_t));
    memcpy(t->name, name, sizeof(t->name));

    t->tid          = handle_alloc(&tid_handle_tbl, t, 0);
    t->owner        = proc;
    t->state        = THREAD_READY;
    t->assigned_cpu = UINT32_MAX;
    t->policy       = policy;

    dlist_init(&t->process_node);
    dlist_init(&t->wait_node);
    dlist_init(&t->join_queue);

    struct sched_class* sc = get_sched_class(policy);
    t->sched_class         = sc;

    if (sc->init_task) {
        sc->init_task(t, arg);
    }

    if (!arch_thread_init(t, entry, args)) {
        kmem_cache_free(thread_cache, t);
        return nullptr;
    }

    acquire_spinlock(&proc->lock);
    process_insert_thread(proc, t);
    proc->thread_count++;
    release_spinlock(&proc->lock);

    return t;
}

thread_t* thread_create(
    const char* name,
    process_t* proc,
    uint8_t policy,
    void (*entry)(void*),
    void* args,
    ...
) {
    if (!thread_cache) {
        thread_cache =
            kmem_cache_create("thread_cache", sizeof(thread_t), _Alignof(thread_t), 0, nullptr);
    }

    va_list list;
    va_start(list, args);
    thread_t* t = thread_create_internal(name, proc, policy, entry, args, list);
    va_end(list);

    return t;
}

thread_t* thread_clone(process_t* target_proc, thread_t* parent, interrupt_trapframe_t* tf) {
    if (!target_proc || !parent || !tf) {
        return nullptr;
    }

    thread_t* child = kmem_cache_alloc(thread_cache);
    if (!child) {
        return nullptr;
    }

    memset(child, 0, sizeof(thread_t));
    child->tid = handle_alloc(&tid_handle_tbl, child, 0);
    if (child->tid == 0) {
        kmem_cache_free(thread_cache, child);
        return nullptr;
    }

    child->owner        = target_proc;
    child->assigned_cpu = UINT32_MAX;
    child->state        = THREAD_READY;
    child->policy       = parent->policy;
    child->sched_class  = parent->sched_class;

    dlist_init(&child->process_node);
    dlist_init(&child->wait_node);
    dlist_init(&child->join_queue);

    memcpy(&child->sched, &parent->sched, sizeof(sched_entity_t));

    child->kernel_stack = (thread_t*)vmalloc(
        kernel_space,
        nullptr,
        KSTACK_SIZE,
        VMM_FLAG_STACK | VMM_FLAG_WRITE | VMM_FLAG_READ,
        CACHE_WRITE_BACK,
        PAGE_SIZE_SMALL
    );

    if (!child->kernel_stack) {
        handle_free(&tid_handle_tbl, child->tid);
        kmem_cache_free(thread_cache, child);
        return nullptr;
    }

    child->kernel_stack_top = (uintptr_t)child->kernel_stack + KSTACK_SIZE;

    arch_thread_clone(child, tf);

    acquire_spinlock(&target_proc->lock);
    process_insert_thread(target_proc, child);
    target_proc->thread_count++;
    release_spinlock(&target_proc->lock);

    return child;
}

static void reaper_enqueue_dead_thread(thread_t* t) {
    if (!t) {
        return;
    }

    acquire_spinlock(&dead_thread_lock);

    dlist_add_tail(&t->wait_node, &dead_thread_list);
    wake_up_all(&reaper_wait_queue);

    release_spinlock(&dead_thread_lock);
}

void thread_destroy(thread_t* t) {
    if (!t) {
        return;
    }

    scheduler_remove_thread(t);

    wake_up_all(&t->join_queue);

    if (t->owner) {
        acquire_spinlock(&t->owner->lock);

        if (!dlist_empty(&t->process_node)) {
            dlist_del(&t->process_node);
            dlist_init(&t->process_node);
            t->owner->thread_count--;
        }

        release_spinlock(&t->owner->lock);
    }

    if (t == smp_current_core()->curr_thread) {
        t->state = THREAD_TERMINATED;
        reaper_enqueue_dead_thread(t);
        scheduler_yield();
        PANIC("THREAD: execution continue after self-destruction");
    }

    arch_thread_destroy(t);
    handle_free(&tid_handle_tbl, t->tid);
    kmem_cache_free(thread_cache, t);
}

void thread_exit(int exit_code) {
    arch_disable_interrupts();
    per_cpu_data_t* cpu = smp_current_core();
    thread_t* curr      = cpu->curr_thread;

    curr->exit_code = exit_code;
    wake_up_all(&curr->join_queue);

    bool is_last_thread = false;
    if (curr->owner) {
        acquire_spinlock(&curr->owner->lock);

        if (curr->owner->thread_count <= 1) {
            is_last_thread = true;
        }

        release_spinlock(&curr->owner->lock);
    }

    if (is_last_thread && curr->owner->state == PROCESS_ALIVE) {
        process_exit(exit_code);
    }

    curr->state = THREAD_TERMINATED;
    scheduler_remove_thread(curr);
    reaper_enqueue_dead_thread(curr);
    scheduler_yield();

    PANIC("THREAD: Escaped the afterlife");
}

void thread_join(thread_t* t, int* exit_code) {
    if (!t) {
        return;
    }

    while (t->state != THREAD_TERMINATED) {
        sleep_on_queue(&t->join_queue);
    }

    if (exit_code) {
        *exit_code = t->exit_code;
    }
}

void reaper_task_entry(void*) {
    KLOG_INFO("REAPER: background cleanup thread started\n");

    while (true) {
        acquire_spinlock(&dead_thread_lock);

        if (dlist_empty(&dead_thread_list)) {
            release_spinlock(&dead_thread_lock);
            sleep_on_queue(&reaper_wait_queue);
            continue;
        }

        struct dlist_head* node = dead_thread_list.next;
        dlist_del(node);

        release_spinlock(&dead_thread_lock);

        thread_t* dead_thread = dlist_entry(node, thread_t, wait_node);
        KLOG_DEBUG("REAPER: cleaning up dead thread tid=%u\n", dead_thread->tid);

        arch_thread_destroy(dead_thread);
        handle_free(&tid_handle_tbl, dead_thread->tid);
        kmem_cache_free(thread_cache, dead_thread);
    }
}