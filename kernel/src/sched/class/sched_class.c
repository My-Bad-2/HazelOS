#include "sched/sched_class.h"

#include "libs/log.h"
#include "libs/spinlock.h"

struct sched_class* sched_classes_head = nullptr;
static qspinlock_t class_lock;

void sched_class_init(void) {
    sched_classes_head = nullptr;
    create_qspinlock(&class_lock);
}

struct sched_class* get_sched_class(int policy_id) {
    acquire_qspinlock(&class_lock);

    struct sched_class* curr = sched_classes_head;
    while (curr) {
        if (curr->policy_id == policy_id) {
            release_qspinlock(&class_lock);
            return curr;
        }

        curr = curr->next;
    }

    release_qspinlock(&class_lock);
    return nullptr;
}

void sched_class_register(struct sched_class* sc) {
    if (!sc) {
        return;
    }

    acquire_qspinlock(&class_lock);

    struct sched_class** link = &sched_classes_head;
    while (*link && (*link)->priority >= sc->priority) {
        if (*link == sc) {
            release_qspinlock(&class_lock);
            KLOG_WARN("SCHED: Class '%s' is already registered\n", sc->name);
            return;
        }

        link = &(*link)->next;
    }

    sc->next = *link;
    *link    = sc;

    release_qspinlock(&class_lock);
    KLOG_INFO(
        "SCHED: Registered class '%s' (policy: %d, priority: %d)\n",
        sc->name,
        sc->policy_id,
        sc->priority
    );
}

bool sched_class_unregister(struct sched_class* sc) {
    if (!sc) {
        return false;
    }

    acquire_qspinlock(&class_lock);

    struct sched_class** link = &sched_classes_head;
    bool found                = false;

    while (*link) {
        if (*link == sc) {
            *link    = sc->next;
            sc->next = nullptr;
            found    = true;
            break;
        }

        link = &(*link)->next;
    }

    release_qspinlock(&class_lock);

    if (found) {
        KLOG_INFO("SCHED: Unregistered class '%s'\n", sc->name);
    }

    return found;
}