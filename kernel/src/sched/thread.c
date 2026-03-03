#include <stdarg.h>
#include <stdint.h>
#include <string.h>

#include "drivers/timer.h"
#include "libs/handles.h"
#include "libs/spinlock.h"
#include "memory/heap.h"
#include "sched/process.h"
#include "sched/sched_class.h"

static kmem_cache_t* thread_cache = nullptr;

static void process_insert_thread(process_t* p, thread_t* t) {
    struct rb_node** link  = &p->thread_tree.rb_node;
    struct rb_node* parent = nullptr;

    while (*link) {
        parent = *link;

        thread_t* entry = rb_entry(parent, thread_t, process_node);

        if (t->tid < entry->tid) {
            link = &parent->rb_left;
        } else {
            link = &parent->rb_right;
        }
    }

    rb_link_node(&t->process_node, parent, link);
    rb_insert_color(&t->process_node, &p->thread_tree);
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
    va_end(args);

    return t;
}

void thread_destroy(thread_t* t) {}