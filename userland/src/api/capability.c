#include "api/capability.h"

#include "syscall.h"

int cap_retype(
    uint64_t untyped_id,
    uint16_t target_type,
    size_t count,
    uint64_t dest_cnode_id,
    uint64_t* out_array
) {
    int status = syscall(
        SYS_CAP_RETYPE,
        (long)untyped_id,
        target_type,
        (long)count,
        (long)dest_cnode_id,
        (long)out_array
    );

    return status;
}

int cap_delegate(
    uint64_t dest_cnode_id,
    uint64_t src_cap_id,
    uint16_t reduced_rights,
    uint64_t* out_cap_id
) {
    return syscall(
        SYS_CAP_DELEGATE,
        (long)dest_cnode_id,
        (long)src_cap_id,
        reduced_rights,
        (long)out_cap_id
    );
}

int cap_revoke(uint64_t target_id) {
    return syscall(SYS_CAP_REVOKE, (long)target_id);
}

int cap_copy(uint64_t dest_cnode_id, uint64_t src_cap_id, uint64_t* out_cap_id) {
    return syscall(SYS_CAP_COPY, (long)dest_cnode_id, (long)src_cap_id, (long)out_cap_id);
}

int cap_mint(
    uint64_t dest_cnode_id,
    uint64_t src_cap_id,
    uint16_t new_rights,
    uint32_t badge,
    uint64_t* out_cap_id
) {
    return syscall(
        SYS_CAP_MINT,
        (long)dest_cnode_id,
        (long)src_cap_id,
        new_rights,
        badge,
        (long)out_cap_id
    );
}