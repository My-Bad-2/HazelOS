#include "sched/sched_class.h"

#include <stdatomic.h>

#include "compiler.h"
#include "libs/log.h"
#include "libs/spinlock.h"

struct sched_class* sched_classes_head = nullptr;
static qspinlock_t class_write_lock;

static _Atomic(struct sched_class*) policy_map[MAX_SCHED_POLICIES];
static atomic_int next_dynamic_id = 16;

void sched_class_init(void) {
    sched_classes_head = nullptr;
    create_qspinlock(&class_write_lock);
    atomic_init(&next_dynamic_id, 16);

    for (int i = 0; i < MAX_SCHED_POLICIES; ++i) atomic_init(&policy_map[i], nullptr);
}

struct sched_class* get_sched_class(int policy_id) {
    if (unlikely(policy_id < 0 || policy_id >= MAX_SCHED_POLICIES)) return nullptr;
    return atomic_load_explicit(&policy_map[policy_id], memory_order_acquire);
}

int sched_class_register(struct sched_class* sc) {
    if (unlikely(!sc)) return -1;

    if (sc->policy_id == SCHED_POLICY_DYNAMIC)
        sc->policy_id = atomic_fetch_add_explicit(&next_dynamic_id, 1, memory_order_relaxed);

    if (unlikely(sc->policy_id >= MAX_SCHED_POLICIES || sc->policy_id < 0)) {
        KLOG_ERROR("SCHED: Policy ID %d exceeds MAX_SCHED_POLICIES\n", sc->policy_id);
        return -1;
    }

    acquire_qspinlock(&class_write_lock);

    if (atomic_load_explicit(&policy_map[sc->policy_id], memory_order_relaxed) != nullptr) {
        release_qspinlock(&class_write_lock);
        KLOG_ERROR("SCHED: Policy ID %d is already registered\n", sc->policy_id);
        return -1;
    }

    struct sched_class** link = &sched_classes_head;
    while (*link && (*link)->priority >= sc->priority) {
        link = &(*link)->next;
    }

    sc->next = *link;
    atomic_store_explicit((_Atomic(struct sched_class*)*)link, sc, memory_order_release);
    atomic_store_explicit(&policy_map[sc->policy_id], sc, memory_order_release);

    release_qspinlock(&class_write_lock);
    KLOG_INFO(
        "SCHED: Registered class '%s' (policy: %d, priority: %d)\n",
        sc->name,
        sc->policy_id,
        sc->priority
    );

    return sc->policy_id;
}

bool sched_class_unregister(struct sched_class* sc) {
    if (unlikely(!sc || sc->policy_id < 0 || sc->policy_id >= MAX_SCHED_POLICIES)) return false;

    acquire_qspinlock(&class_write_lock);

    if (atomic_load_explicit(&policy_map[sc->policy_id], memory_order_relaxed) == sc) {
        atomic_store_explicit(&policy_map[sc->policy_id], nullptr, memory_order_release);
    } else {
        release_qspinlock(&class_write_lock);
        return false;
    }

    struct sched_class** link = &sched_classes_head;
    while (*link) {
        if (*link == sc) {
            *link    = sc->next;
            sc->next = nullptr;
            break;
        }

        link = &(*link)->next;
    }

    release_qspinlock(&class_write_lock);

    KLOG_INFO("SCHED: Unregistered class '%s'\n", sc->name);
    return true;
}