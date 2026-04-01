#ifndef USERLAND_API_MEMORY_H
#define USERLAND_API_MEMORY_H 1

#include <stddef.h>

#define SYS_CATEGORY_MEM 0x0400

#define SYS_MEM_MMAP     (SYS_CATEGORY_MEM | 0x01)
#define SYS_MEM_MUNMAP   (SYS_CATEGORY_MEM | 0x02)
#define SYS_MEM_MREMAP   (SYS_CATEGORY_MEM | 0x03)
#define SYS_MEM_MPROTECT (SYS_CATEGORY_MEM | 0x04)

#define MAP_HUGE_SHIFT 26
#define MAP_HUGE_MASK  0x3f

#define PROT_NONE  0
#define PROT_EXEC  0x01
#define PROT_READ  0x02
#define PROT_WRITE 0x04

#define MAP_SHARED          0x001
#define MAP_PRIVATE         0x002
#define MAP_ANONYMOUS       0x004
#define MAP_FIXED_NOREPLACE 0x008
#define MAP_FIXED           0x010
#define MAP_GROWSDOWN       0x020
#define MAP_HUGETLB         0x040
#define MAP_POPULATE        0x080
#define MAP_STACK           0x100
#define MAP_LOCKED          0x200

#define MAP_HUGE_2MB (21 << MAP_HUGE_SHIFT)
#define MAP_HUGE_1GB (30 << MAP_HUGE_SHIFT)

#define MREMAP_MAYMOVE   0x01
#define MREMAP_FIXED     0x02
#define MREMAP_DONTUNMAP 0x04

typedef long off_t;

void* mmap(void* addr, size_t length, int prot, int flags, int fd, off_t offset);
int munmmap(void* addr, size_t length);
int mprotect(void* addr, size_t length, int prot);
void* mremap(void* old_address, size_t old_size, size_t new_size, int flags, void* new_address);

#endif