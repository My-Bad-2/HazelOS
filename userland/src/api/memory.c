#include "api/memory.h"

#include "syscall.h"

void* mmap(void* addr, size_t length, int prot, int flags, int fd, off_t offset) {
    return (void*)syscall(SYS_MEM_MMAP, (long)addr, (long)length, prot, flags, fd, offset);
}

int mprotect(void* addr, size_t length, int prot) {
    return (int)syscall(SYS_MEM_MPROTECT, (long)addr, (long)length, prot);
}

int munmmap(void* addr, size_t length) {
    return (int)syscall(SYS_MEM_MUNMAP, (long)addr, (long)length);
}

void* mremap(void* old_address, size_t old_size, size_t new_size, int flags, void* new_address) {
    return (
        void*
    )syscall((long)old_address, (long)old_size, (long)new_size, flags, (long)new_address);
}