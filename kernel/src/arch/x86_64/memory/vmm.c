#include "memory/vmm.h"

#include <errno.h>
#include <string.h>

#include "cpu/registers.h"
#include "cpu/smp.h"
#include "libs/elf.h"
#include "libs/log.h"
#include "libs/math.h"
#include "memory/memory.h"
#include "memory/pagemap.h"
#include "memory/paging.h"
#include "memory/vma.h"
#include "sched/process.h"
#include "sched/scheduler.h"

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

    if (ehdr->e_ident[EI_MAG0] != ELFMAG0 || ehdr->e_ident[EI_MAG1] != ELFMAG1 ||
        ehdr->e_ident[EI_MAG2] != ELFMAG2 || ehdr->e_ident[EI_MAG3] != ELFMAG3) {
        KLOG_INIT_FAIL();
        PANIC("VMM: invalid kernel ELF header\n");
    }

    Elf64_Phdr* phdr = (Elf64_Phdr*)(kernel_base + ehdr->e_phoff);

    for (int i = 0; i < ehdr->e_phnum; ++i) {
        Elf64_Phdr* segment = &phdr[i];

        if (segment->p_type != PT_LOAD) {
            continue;
        }

        uintptr_t virt_start = segment->p_vaddr;
        uintptr_t virt_end   = virt_start + segment->p_memsz;

        // Ensure that phys base delta = PhysicalBase - VirtualBase
        uintptr_t phys_start         = virt_start + phys_base_delta;
        uintptr_t aligned_virt_start = align_down(virt_start, PAGE_SIZE_SMALL);
        uintptr_t aligned_virt_end   = align_up(virt_end, PAGE_SIZE_SMALL);
        uintptr_t aligned_phys_start = align_down(phys_start, PAGE_SIZE_SMALL);

        size_t aligned_len = aligned_virt_end - aligned_virt_start;
        uint32_t map_flags = vmm_get_segment_flags(segment->p_flags);

        pagemap_map_args_t args = {
            .virt_addr  = (void*)aligned_virt_start,
            .phys_addr  = (void*)aligned_phys_start,
            .length     = aligned_len,
            .flags      = map_flags,
            .cache      = CACHE_WRITE_BACK,
            .page_size  = PAGE_SIZE_MEDIUM,
            .pkey       = 0,
            .skip_flush = false
        };

        if (is_aligned(aligned_virt_start, PAGE_SIZE_MEDIUM) &&
            is_aligned(aligned_phys_start, PAGE_SIZE_MEDIUM) && (aligned_len >= PAGE_SIZE_MEDIUM)) {
            args.page_size = PAGE_SIZE_MEDIUM;
        }

        if (!pagemap_map(map, &args)) {
            KLOG_INIT_FAIL();
            PANIC("VMM: Failed to map kernel segment %d\n", i);
        }
    }
}

struct vmm_fault_info arch_decode_fault_error(uintptr_t error_code) {
    struct vmm_fault_info info = {0};

    info.is_present = (error_code & X86_PAGE_FAULT_PRESENT) != 0;
    info.is_write   = (error_code & X86_PAGE_FAULT_WRITE) != 0;
    info.is_user    = (error_code & X86_PAGE_FAULT_USER) != 0;
    info.is_exec    = (error_code & X86_PAGE_FAULT_INSTRUCTION_FETCH) != 0;

    return info;
}

__attribute__((force_align_arg_pointer)) void pf_handler(interrupt_trapframe_t* tf) {
    uintptr_t fault_addr = read_cr2();
    thread_t* t          = smp_current_core()->curr_thread;
    if (!t || !t->owner) {
        PANIC("Early boot page fault at %p (RIP: %p)!\n", fault_addr, tf->rip);
    }

    process_t* proc   = t->owner;
    vm_space_t* space = &proc->space;

    if (vmm_handle_fault(space, fault_addr, tf->error_code)) {
        return;
    }

    if (tf->error_code & X86_PAGE_FAULT_USER) {
        process_exit(-EFAULT);
    } else {
        PANIC("Kernel page fault at %p! (RIP: %p)", fault_addr, tf->rip);
    }
}