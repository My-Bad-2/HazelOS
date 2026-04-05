#include "drivers/loader.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "boot/boot.h"
#include "boot/limine.h"
#include "libs/elf.h"
#include "libs/log.h"
#include "libs/math.h"
#include "memory/memory.h"
#include "memory/pagemap.h"
#include "memory/vma.h"
#include "sched/process.h"
#include "sched/scheduler.h"

#if defined(__x86_64__)
#define TARGET_ELF_MACHINE EM_X86_64
#elif defined(__aarch64__)
#define TARGET_ELF_MACHINE EM_AARCH64
#elif defined(__riscv)
#define TARGET_ELF_MACHINE EM_RISCV
#else
#error "Unsupported architecture for ELF Loader"
#endif

// NOLINTNEXTLINE
process_t* init_process = nullptr;

static inline bool validate_elf(Elf64_Ehdr* ehdr) {
    if (!ehdr) {
        return false;
    }

    if (memcmp(ehdr->e_ident, ELFMAG, SELFMAG) != 0) {
        KLOG_ERROR("ELF: Invalid Magic\n");
        return false;
    }

    if (ehdr->e_ident[EI_CLASS] != ELFCLASS64) {
        KLOG_ERROR("ELF: Not 64-bit executable\n");
        return false;
    }

    if (ehdr->e_machine != TARGET_ELF_MACHINE) {
        KLOG_ERROR("ELF: Architecture mismatch\n");
        return false;
    }

    if (ehdr->e_type != ET_EXEC && ehdr->e_type != ET_DYN) {
        KLOG_ERROR("ELF: Not executable\n");
        return false;
    }

    return true;
}

static bool load_segment(process_t* proc, Elf64_Phdr* phdr, void* base) {
    uint8_t vmm_flags = VMM_FLAG_USER | VMM_FLAG_READ;

    if (phdr->p_flags & PF_W) {
        vmm_flags |= VMM_FLAG_WRITE;
    }

    if (phdr->p_flags & PF_X) {
        vmm_flags |= VMM_FLAG_EXECUTE;
    }

    uintptr_t vaddr_start = phdr->p_vaddr;
    uintptr_t vaddr_end   = vaddr_start + phdr->p_memsz;
    uintptr_t page_start  = align_down(vaddr_start, PAGE_SIZE_SMALL);
    uintptr_t page_end    = align_up(vaddr_end, PAGE_SIZE_SMALL);

    if (vaddr_end < vaddr_start) {
        return false;
    }

    for (uintptr_t curr_v = page_start; curr_v < page_end; curr_v += PAGE_SIZE_SMALL) {
        vmalloc(
            proc->vspace,
            (void*)curr_v,
            PAGE_SIZE_SMALL,
            vmm_flags | VMM_FLAG_FIXED,
            CACHE_WRITE_BACK,
            PAGE_SIZE_SMALL
        );

        // Technically any user page is accessible to the kernel via HHDM
        uintptr_t phys_addr = pagemap_translate(proc->map, curr_v);
        void* virt          = (void*)to_higher_half(phys_addr);

        size_t offset_in_page = (curr_v < vaddr_start) ? (vaddr_start - curr_v) : 0;
        size_t bytes_to_copy  = 0;

        size_t file_offset     = phdr->p_offset + (curr_v + offset_in_page - vaddr_start);
        size_t relative_offset = (curr_v + offset_in_page) - vaddr_start;

        if (relative_offset < phdr->p_filesz) {
            bytes_to_copy = phdr->p_filesz - relative_offset;

            if (bytes_to_copy > (PAGE_SIZE_SMALL - offset_in_page)) {
                bytes_to_copy = PAGE_SIZE_SMALL - offset_in_page;
            }
        }

        memset(virt, 0, PAGE_SIZE_SMALL);

        if (bytes_to_copy > 0) {
            void* src = (void*)((uint8_t*)base + file_offset);
            memcpy((uint8_t*)virt + offset_in_page, src, bytes_to_copy);
        }
    }

    return true;
}

thread_t* load_elf(void* address) {
    if (!address) {
        KLOG_ERROR("Loader: Cannot locate ELF file!\n");
        return nullptr;
    }

    Elf64_Ehdr* ehdr = (Elf64_Ehdr*)address;

    if (!validate_elf(ehdr)) {
        return nullptr;
    }

    struct vm_space* vspace = vmm_create_space(false);

    init_process = process_create("user_init", false, vspace, nullptr, nullptr, nullptr, nullptr);
    if (!init_process) {
        KLOG_ERROR("Loader: Failed to create process\n");
        return nullptr;
    }

    Elf64_Phdr* phdrs = (Elf64_Phdr*)((uint8_t*)ehdr + ehdr->e_phoff);
    for (int i = 0; i < ehdr->e_phnum; ++i) {
        if (phdrs[i].p_type == PT_LOAD) {
            if (!load_segment(init_process, &phdrs[i], address)) {
                return nullptr;
            }
        }
    }

    thread_t* t =
        thread_create("user_init", init_process, SCHED_NORMAL, (void*)ehdr->e_entry, nullptr, 0);

    return t;
}

void launch_user_init(void) {
    struct limine_file* file = module_request.response->modules[0];

    thread_t* t = load_elf(file->address);
    scheduler_add_thread(t);
}