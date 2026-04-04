#ifndef KERNEL_CORE_POSIX_EMUL_H
#define KERNEL_CORE_POSIX_EMUL_H 1

#include "libs/dlist.h"

struct process;

struct posix_child {
    struct dlist_head node;
    uint64_t pid;
    uint64_t proc_cap_id;
};

int posix_register_child_emulation(struct process* parent, uint64_t pid, uint64_t proc_cap_id);
uint64_t posix_get_child_cap(struct process* parent, uint64_t pid);
void posix_unregister_child(struct process* parent, uint64_t pid);
void posix_cleanup_all_children(struct process* parent);

#endif