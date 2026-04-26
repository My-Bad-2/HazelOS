#ifndef USERLAND_API_MEMORY_H
#define USERLAND_API_MEMORY_H 1

#include <stddef.h>
#include <stdint.h>

#define SYS_CATEGORY_MEM 0x0400

#define SYS_MEM_MAP     (SYS_CATEGORY_MEM | 0x01)
#define SYS_MEM_UNMAP   (SYS_CATEGORY_MEM | 0x02)
#define SYS_MEM_PROTECT (SYS_CATEGORY_MEM | 0x03)
#define SYS_VMO_CREATE  (SYS_CATEGORY_MEM | 0x04)
#define SYS_VMO_RESIZE  (SYS_CATEGORY_MEM | 0x05)
#define SYS_VMO_READ    (SYS_CATEGORY_MEM | 0x06)
#define SYS_VMO_WRITE   (SYS_CATEGORY_MEM | 0x07)
#define SYS_VMO_CLONE   (SYS_CATEGORY_MEM | 0x08)
#define SYS_MEM_WPKRU   (SYS_CATEGORY_MEM | 0x09)

#define VMO_CREATE_RAM       0x0001u  // Standard Zeroed RAM
#define VMO_CREATE_PHYSICAL  0x0002u  // Direct physical memory (MMIO)
#define VMO_CREATE_RESIZABLE 0x0004u

#define VSPACE_PROT_READ  0x0001u
#define VSPACE_PROT_WRITE 0x0002u
#define VSPACE_PROT_EXEC  0x0004u

#define VSPACE_MAP_EXACT     0x0100u   // Must map exactly at hint_addr or fail
#define VSPACE_MAP_OVERWRITE 0x0200u   // Map at hint_addr, destroying existing mappings
#define VSPACE_MAP_SHADOW    0x0400u   // Create a Copy-On-Write private clone of the VMO
#define VSPACE_MAP_STACK     0x0800u   // Allocates a guard page automatically at the bottom
#define VSPACE_MAP_LAZY      0x1000u   // Demand paging (allocate physical frames on fault)
#define VSPACE_MAP_WIRE      0x2000u   // Populate immediately AND lock into RAM (No eviction)
#define VSPACE_MAP_POPULATE  0x4000u   // Populate immediately, but allow future eviction
#define VSPACE_MAP_PAGE_2M   0x8000u   // Force 2MB Superpages
#define VSPACE_MAP_PAGE_1G   0x10000u  // Force 1GB Hugepages

#define PKEY_FLAG_ACCESS_DISABLE 0x1u  // Blocks data reads and writes.
#define PKEY_FLAG_WRITE_DISABLE  0x2u  // Blocks writes when ACCESS_DISABLE is clear.

int vmo_create(size_t size, uint32_t vmo_flags, uint64_t* out_vmo_cap);
int vmo_resize(uint64_t vmo_cap, size_t new_size);
int vmo_read(uint64_t vmo_cap, void* buffer, size_t offset, size_t size);
int vmo_write(uint64_t vmo_cap, const void* buffer, size_t offset, size_t size);
int vmo_clone(
    uint64_t src_vmo_cap,
    size_t offset,
    size_t size,
    uint32_t flags,
    uint64_t* out_vmo_cap
);

uintptr_t vspace_map(
    uint64_t vspace_cap,
    uint64_t vmo_cap,
    size_t vmo_offset,
    uintptr_t hint_addr,
    size_t size,
    uint32_t map_flags
);
int vspace_unmap(uint64_t vspace_cap, uintptr_t addr, size_t size);
int vspace_protect(uint64_t vspace_cap, uintptr_t addr, size_t size, uint32_t new_prots);
int vspace_pkey_alloc(uint64_t vspace_cap, uint32_t flags);

#endif