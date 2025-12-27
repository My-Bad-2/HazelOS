#include "memory/vmm.h"

#include <errno.h>
#include <string.h>

#include "libs/elf.h"
#include "libs/log.h"
#include "libs/math.h"
#include "memory/memory.h"
#include "memory/pagemap.h"

static uint32_t vmm_get_segment_flags(uint32_t elf_flags) {
    uint32_t flags = 0;

    if (elf_flags & PF_R) {
        flags |= VMM_FLAG_READ;
    }

    if (elf_flags & PF_W) {
        flags |= VMM_FLAG_WRITE;
    }

    if (elf_flags & PF_X) {
        flags |= VMM_FLAG_EXECUTE;
    }

    return flags;
}

void vmm_map_kernel(pagemap_t* map, uintptr_t kernel_base, uintptr_t phys_base_delta) {
    Elf64_Ehdr* ehdr = (Elf64_Ehdr*)kernel_base;

    // 1. Validate ELF Magic
    if (ehdr->e_ident[EI_MAG0] != ELFMAG0 || ehdr->e_ident[EI_MAG1] != ELFMAG1 ||
        ehdr->e_ident[EI_MAG2] != ELFMAG2 || ehdr->e_ident[EI_MAG3] != ELFMAG3) {
        errno = ENOEXEC;
        PANIC("VMM: invalid kernel ELF header\n");
        return;
    }

    Elf64_Phdr* phdr = (Elf64_Phdr*)(kernel_base + ehdr->e_phoff);

    for (int i = 0; i < ehdr->e_phnum; ++i) {
        Elf64_Phdr* segment = &phdr[i];

        // We only map LOAD segment
        if (segment->p_type != PT_LOAD) {
            continue;
        }

        uintptr_t virt_start = segment->p_vaddr;
        uintptr_t virt_end   = virt_start + segment->p_memsz;

        // Ensure that phys base delta = PhysicalBase - VirtualBase
        uintptr_t phys_start = virt_start + phys_base_delta;

        uintptr_t aligned_virt_start = align_down(virt_start, PAGE_SIZE_SMALL);
        uintptr_t aligned_virt_end   = align_up(virt_end, PAGE_SIZE_SMALL);

        uintptr_t aligned_phys_start = align_down(phys_start, PAGE_SIZE_SMALL);

        size_t aligned_len = aligned_virt_end - aligned_virt_start;

        uint32_t map_flags = vmm_get_segment_flags(segment->p_flags);

        KLOG_DEBUG(
            "VMM: map kernel segment idx=%d virt=0x%lx phys=0x%lx len=0x%zx flags=0x%x\n",
            i,
            aligned_virt_start,
            aligned_phys_start,
            aligned_len,
            map_flags
        );

        pagemap_map_args_t args = {
            .virt_addr  = (void*)aligned_virt_start,
            .phys_addr  = (void*)aligned_phys_start,
            .length     = aligned_len,
            .flags      = map_flags,
            .cache      = CACHE_WRITE_BACK,
            .page_size  = PAGE_SIZE_SMALL,
            .pkey       = 0,
            .skip_flush = false
        };

        if (is_aligned(aligned_virt_start, PAGE_SIZE_MEDIUM) &&
            is_aligned(aligned_phys_start, PAGE_SIZE_MEDIUM) && (aligned_len >= PAGE_SIZE_MEDIUM)) {
            args.page_size = PAGE_SIZE_MEDIUM;
        }

        if (!pagemap_map(map, args)) {
            int err = errno ? errno : ENOMEM;
            errno   = err;
            PANIC(
                "VMM: failed to map kernel segment idx=%d virt=0x%lx phys=0x%lx len=0x%zx "
                "errno=%d\n",
                i,
                aligned_virt_start,
                aligned_phys_start,
                aligned_len,
                err
            );
            return;
        }
    }
}