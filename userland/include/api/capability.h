#ifndef USERLAND_API_CAPABILITY_H
#define USERLAND_API_CAPABILITY_H

#include <stddef.h>
#include <stdint.h>

#define SYS_CATEGORY_CAP 0x0100

#define SYS_CAP_RETYPE   (SYS_CATEGORY_CAP | 0x01)  // Carve objects from untyped memory
#define SYS_CAP_DELEGATE (SYS_CATEGORY_CAP | 0x02)  // Grant a capability to another CNode
#define SYS_CAP_REVOKE   (SYS_CATEGORY_CAP | 0x03)  // Recursively destroy derived caps
#define SYS_CAP_COPY     (SYS_CATEGORY_CAP | 0x04)  // Duplicate a cap within the same CNode
#define SYS_CAP_MINT     (SYS_CATEGORY_CAP | 0x05)  // Copy a cap but downgrade its rights

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Retypes a block of Untyped memory into kernel objects.
 * @param untyped_id     The capability ID of the physical memory block.
 * @param target_type    The object type to create (e.g., OBJ_CHANNEL).
 * @param count          How many objects to create.
 * @param dest_cnode_id  The CNode where the new capabilities should be placed.
 * @param out_array      Pointer to a user buffer to store the new Capability IDs.
 * @return               NOISE_OK on success, or negative error code.
 */
int cap_retype(
    uint64_t untyped_id,
    uint16_t target_type,
    size_t count,
    uint64_t dest_cnode_id,
    uint64_t* out_array
);

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
 * @param target_id      The capability to revoke.
 */
int cap_revoke(uint64_t target_id);

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

#ifdef __cplusplus
}
#endif

#endif