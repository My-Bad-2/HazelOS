#ifndef USERLAND_API_CAPABILITY_H
#define USERLAND_API_CAPABILITY_H

#include <stddef.h>
#include <stdint.h>

#define SYS_CATEGORY_CAP 0x0100

#define SYS_CAP_DELEGATE (SYS_CATEGORY_CAP | 0x01)  // Grant a capability to another CNode
#define SYS_CAP_CLOSE    (SYS_CATEGORY_CAP | 0x02)  // Close a cap
#define SYS_CAP_COPY     (SYS_CATEGORY_CAP | 0x03)  // Duplicate a cap within the same CNode
#define SYS_CAP_MINT     (SYS_CATEGORY_CAP | 0x04)  // Copy a cap but downgrade its rights
#define SYS_CAP_ALIAS    (SYS_CATEGORY_CAP | 0x05)

// Rights
#define RIGHT_READ         (1 << 0)
#define RIGHT_WRITE        (1 << 1)
#define RIGHT_EXECUTE      (1 << 2)
#define RIGHT_SEND         (1 << 3)
#define RIGHT_RECEIVE      (1 << 4)
#define RIGHT_WAIT         (1 << 5)
#define RIGHT_GRANT        (1 << 6)
#define RIGHT_SIGNAL       (1 << 11)
#define RIGHT_CNODE_MUTATE (1 << 14)
#define RIGHT_WEAK         (1 << 15)
#define RIGHT_ALL          (0x7fff)

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Moves/Grants a capability to another CNode with potentially reduced rights.
 * @param dest_cnode_id  The target CNode.
 * @param src_cap_id     The capability to delegate.
 * @param reduced_rights The maximum rights the new capability should have.
 * @param out_cap_id     Pointer to store the newly created Capability ID.
 */
int cap_delegate(
    uint64_t dest_cnode_id,
    uint64_t src_cap_id,
    uint16_t reduced_rights,
    uint64_t* out_cap_id
);

/**
 * Recursively destroys a capability and all objects derived from it.
 * @param target_id      The capability to close.
 */
int cap_close(uint64_t target_id);

/**
 * Duplicates a capability within the same CNode with identical rights.
 * @param dest_cnode_id  The target CNode.
 * @param src_cap_id     The capability to copy.
 * @param out_cap_id     Pointer to store the new Capability ID.
 */
int cap_copy(uint64_t dest_cnode_id, uint64_t src_cap_id, uint64_t* out_cap_id);

/**
 * Duplicates a capability, applying downgraded rights and a secure badge identity.
 * @param dest_cnode_id  The target CNode.
 * @param src_cap_id     The capability to mint.
 * @param new_rights     The downgraded rights mask.
 * @param badge          The unforgeable 32-bit identity to stamp on the capability.
 * @param out_cap_id     Pointer to store the new Capability ID.
 */
int cap_mint(
    uint64_t dest_cnode_id,
    uint64_t src_cap_id,
    uint16_t new_rights,
    uint32_t badge,
    uint64_t* out_cap_id
);

/**
 * Creates a duplicate capability within the current process, optionally reducing its rights.
 * @param src_cap_id     The capability to duplicate.
 * @param reduced_rights The maximum rights the new alias should hold.
 * @param out_cap_id     Pointer to store the new alias ID.
 * @return               NOISE_OK on success, or a negative error code.
 */
int cap_alias(uint64_t src_cap_id, uint16_t reduced_rights, uint64_t* out_cap_id);

#ifdef __cplusplus
}
#endif

#endif