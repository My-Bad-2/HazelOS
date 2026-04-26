#include "api/memory.h"

#include <stdint.h>

#include "syscall.h"

int vmo_create(size_t size, uint32_t vmo_flags, uint64_t* out_vmo_cap) {
    return syscall(SYS_VMO_CREATE, (long)size, vmo_flags, (long)out_vmo_cap);
}

int vmo_resize(uint64_t vmo_cap, size_t new_size) {
    return syscall(SYS_VMO_RESIZE, (long)vmo_cap, (long)new_size);
}

uintptr_t vspace_map(
    uint64_t vspace_cap,
    uint64_t vmo_cap,
    size_t vmo_offset,
    uintptr_t hint_addr,
    size_t size,
    uint32_t map_flags
) {
    return (uintptr_t)syscall(
        SYS_MEM_MAP,
        (long)vspace_cap,
        (long)vmo_cap,
        (long)vmo_offset,
        (long)hint_addr,
        (long)size,
        (long)map_flags
    );
}

int vspace_unmap(uint64_t vspace_cap, uintptr_t addr, size_t size) {
    return syscall(SYS_MEM_UNMAP, (long)vspace_cap, (long)addr, (long)size);
}

int vspace_protect(uint64_t vspace_cap, uintptr_t addr, size_t size, uint32_t new_prots) {
    return syscall(SYS_MEM_PROTECT, (long)vspace_cap, (long)addr, (long)size, new_prots);
}

int vmo_read(uint64_t vmo_cap, void* buffer, size_t offset, size_t size) {
    return syscall(SYS_VMO_READ, (long)vmo_cap, (long)buffer, (long)offset, (long)size);
}

int vmo_write(uint64_t vmo_cap, const void* buffer, size_t offset, size_t size) {
    return syscall(SYS_VMO_WRITE, (long)vmo_cap, (long)buffer, (long)offset, (long)size);
}

int vmo_clone(
    uint64_t src_vmo_cap,
    size_t offset,
    size_t size,
    uint32_t flags,
    uint64_t* out_vmo_cap
) {
    return syscall(
        SYS_VMO_CLONE,
        (long)src_vmo_cap,
        (long)offset,
        (long)size,
        flags,
        (long)out_vmo_cap
    );
}

int vspace_pkey_alloc(uint64_t vspace_cap, uint32_t flags) {
    return syscall(SYS_MEM_WPKRU, (long)vspace_cap, flags);
}