#include <llvm-libc-macros/generic-error-number-macros.h>

#include "compiler.h"
#include "core/capability.h"
#include "core/posix_emul.h"
#include "memory/heap.h"
#include "sched/process.h"

static kmem_cache_t* posix_child_cache = nullptr;

static void init_posix_cache(void) {
    if (!posix_child_cache)
        posix_child_cache = kmem_cache_create(
            "posix_child_cache",
            sizeof(struct posix_child),
            _Alignof(struct posix_child),
            0,
            nullptr
        );
}

int posix_register_child_emulation(process_t* parent, uint64_t pid, uint64_t proc_cap_id) {
    if (unlikely(!posix_child_cache)) init_posix_cache();

    struct posix_child* entry = kmem_cache_alloc(posix_child_cache);
    if (unlikely(!entry)) return -ENOMEM;

    entry->pid         = pid;
    entry->proc_cap_id = proc_cap_id;

    size_t flags = acquire_qinterrupt_lock(&parent->posix_lock);
    dlist_add_tail(&entry->node, &parent->posix_children);
    release_qinterrupt_lock(&parent->posix_lock, flags);

    return 0;
}

uint64_t posix_get_child_cap(process_t* parent, uint64_t pid) {
    uint64_t cap_id = 0;

    size_t flags = acquire_qinterrupt_lock(&parent->posix_lock);

    struct dlist_head* pos;
    dlist_for_each(pos, &parent->posix_children) {
        struct posix_child* entry = dlist_entry(pos, struct posix_child, node);
        if (entry->pid == pid) {
            cap_id = entry->proc_cap_id;
            break;
        }
    }

    release_qinterrupt_lock(&parent->posix_lock, flags);
    return cap_id;
}

void posix_unregister_child(process_t* parent, uint64_t pid) {
    size_t flags = acquire_qinterrupt_lock(&parent->posix_lock);

    struct dlist_head* pos;
    struct dlist_head* n;
    dlist_for_each_safe(pos, n, &parent->posix_children) {
        struct posix_child* entry = dlist_entry(pos, struct posix_child, node);

        if (entry->pid == pid) {
            dlist_del(&entry->node);
            cap_close(parent->root_cnode, entry->proc_cap_id);
            kmem_cache_free(posix_child_cache, entry);
            break;
        }
    }

    release_qinterrupt_lock(&parent->posix_lock, flags);
}

void posix_cleanup_all_children(process_t* parent) {
    size_t flags = acquire_qinterrupt_lock(&parent->posix_lock);

    struct dlist_head* pos;
    struct dlist_head* n;
    dlist_for_each_safe(pos, n, &parent->posix_children) {
        struct posix_child* entry = dlist_entry(pos, struct posix_child, node);
        dlist_del(&entry->node);

        cap_close(parent->root_cnode, entry->proc_cap_id);
        kmem_cache_free(posix_child_cache, entry);
    }

    release_qinterrupt_lock(&parent->posix_lock, flags);
}