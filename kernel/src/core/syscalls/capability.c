#include "core/capability.h"

#include <stdatomic.h>
#include <stdint.h>

#include "compiler.h"
#include "core/errors.h"
#include "core/syscalls.h"
#include "cpu/exception.h"
#include "cpu/smp.h"

uint64_t sys_cap_delegate(struct interrupt_trapframe* regs) {
    struct cnode* root_cnode = smp_current_core()->curr_thread->owner->root_cnode;

    const uint64_t dest_cnode_id  = SYSCALL_FIRST_ARG(regs);
    const uint64_t src_cap_id     = SYSCALL_SECOND_ARG(regs);
    const uint16_t reduced_rights = SYSCALL_THIRD_ARG(regs);
    uint64_t* new_cap_id          = (uint64_t*)SYSCALL_FOURTH_ARG(regs);

    struct capability* src_cap = cap_lookup(root_cnode, src_cap_id, RIGHT_GRANT);
    if (!src_cap) return (uint64_t)ERR_INVALID_CAP;

    struct capability* dest_cnode_cap = cap_lookup(root_cnode, dest_cnode_id, RIGHT_CNODE_MUTATE);
    if (!dest_cnode_cap || dest_cnode_cap->type != CAP_TYPE_CNODE) return (uint64_t)ERR_INVALID_CAP;

    struct cnode* dest_cnode =
        (struct cnode*)atomic_load_explicit(&dest_cnode_cap->object_ptr, memory_order_acquire);

    uint64_t local_new_id;
    struct capability* new_cap = cap_alloc(dest_cnode, &local_new_id);
    if (!new_cap) return (uint64_t)ERR_NO_MEM;

    int status = cap_delegate(src_cap, new_cap, reduced_rights);
    if (status == ERR_OK && write_cap_out(new_cap_id, local_new_id)) return ERR_OK;

    cap_close(root_cnode, local_new_id);
    return (uint64_t)status;
}

uint64_t sys_cap_close(struct interrupt_trapframe* regs) {
    struct cnode* root_cnode = smp_current_core()->curr_thread->owner->root_cnode;
    return (uint64_t)cap_close(root_cnode, SYSCALL_FIRST_ARG(regs));
}

uint64_t sys_cap_copy(struct interrupt_trapframe* regs) {
    struct cnode* root_cnode     = smp_current_core()->curr_thread->owner->root_cnode;
    const uint64_t dest_cnode_id = SYSCALL_FIRST_ARG(regs);
    const uint64_t src_cap_id    = SYSCALL_SECOND_ARG(regs);
    uint64_t* new_cap_id         = (uint64_t*)SYSCALL_THIRD_ARG(regs);

    struct capability* src_cap = cap_lookup(root_cnode, src_cap_id, RIGHT_GRANT);
    if (!src_cap) return (uint64_t)ERR_INVALID_CAP;

    struct capability* dest_cnode_cap = cap_lookup(root_cnode, dest_cnode_id, RIGHT_CNODE_MUTATE);
    if (!dest_cnode_cap || dest_cnode_cap->type != CAP_TYPE_CNODE) return (uint64_t)ERR_INVALID_CAP;

    struct cnode* dest_cnode =
        (struct cnode*)atomic_load_explicit(&dest_cnode_cap->object_ptr, memory_order_acquire);

    uint64_t local_new_id;
    struct capability* new_cap = cap_alloc(dest_cnode, &local_new_id);
    if (!new_cap) return (uint64_t)ERR_NO_MEM;

    int status = cap_delegate(src_cap, new_cap, RIGHT_ALL);
    if (status == ERR_OK && write_cap_out(new_cap_id, local_new_id)) return ERR_OK;

    cap_close(dest_cnode, local_new_id);
    return (uint64_t)status;
}

uint64_t sys_cap_mint(struct interrupt_trapframe* regs) {
    struct cnode* root_cnode = smp_current_core()->curr_thread->owner->root_cnode;
    uint64_t dest_cnode_id   = SYSCALL_FIRST_ARG(regs);
    uint64_t src_cap_id      = SYSCALL_SECOND_ARG(regs);
    uint16_t new_rights      = SYSCALL_THIRD_ARG(regs);
    uint32_t badge_val       = SYSCALL_FOURTH_ARG(regs);
    uint64_t* new_cap_id     = (uint64_t*)SYSCALL_FIFTH_ARG(regs);

    struct capability* src_cap = cap_lookup(root_cnode, src_cap_id, RIGHT_GRANT);
    if (!src_cap) return (uint64_t)ERR_INVALID_CAP;

    struct capability* dest_cnode_cap = cap_lookup(root_cnode, dest_cnode_id, RIGHT_CNODE_MUTATE);
    if (!dest_cnode_cap || dest_cnode_cap->type != CAP_TYPE_CNODE) return (uint64_t)ERR_INVALID_CAP;

    struct cnode* dest_cnode =
        (struct cnode*)atomic_load_explicit(&dest_cnode_cap->object_ptr, memory_order_acquire);

    uint64_t local_new_id;
    struct capability* new_cap = cap_alloc(dest_cnode, &local_new_id);
    if (!new_cap) return (uint64_t)ERR_NO_MEM;

    int status = cap_delegate(src_cap, new_cap, new_rights);
    if (status == ERR_OK) {
        if (!write_cap_out(new_cap_id, local_new_id)) return (uint64_t)ERR_INVALID;
        new_cap->badge = badge_val;
        return ERR_OK;
    }

    cap_close(dest_cnode, local_new_id);
    return (uint64_t)status;
}

uint64_t sys_cap_alias(struct interrupt_trapframe* regs) {
    struct cnode* root_cnode = smp_current_core()->curr_thread->owner->root_cnode;
    uint64_t src_cap_id      = SYSCALL_FIRST_ARG(regs);
    uint16_t reduced_rights  = SYSCALL_SECOND_ARG(regs);
    uint64_t* new_cap_id     = (uint64_t*)SYSCALL_THIRD_ARG(regs);

    struct capability* src_cap = cap_lookup(root_cnode, src_cap_id, RIGHT_GRANT);
    if (unlikely(!src_cap)) return (uint64_t)ERR_INVALID_CAP;

    uint64_t local_new_id;
    struct capability* new_cap = cap_alloc(root_cnode, &local_new_id);
    if (unlikely(!new_cap)) return (uint64_t)ERR_NO_MEM;

    int status = cap_delegate(src_cap, new_cap, reduced_rights);
    if (status == ERR_OK && write_cap_out(new_cap_id, local_new_id)) return ERR_OK;

    cap_close(root_cnode, local_new_id);
    return (uint64_t)status;
}