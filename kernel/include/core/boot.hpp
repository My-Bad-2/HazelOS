#ifndef KERNEL_CORE_BOOT_HPP
#define KERNEL_CORE_BOOT_HPP 1

#include <cstdint>

#include "external/limine.h"

namespace kernel {
namespace boot {
std::uintptr_t get_hhdm_offset() noexcept;

extern volatile limine_entry_point_request kernel_entry_point;
extern volatile limine_hhdm_request hhdm_request;
extern volatile limine_framebuffer_request framebuffer_request;
extern volatile limine_memmap_request memmap_request;
extern volatile limine_executable_address_request kernel_addr_request;
extern volatile limine_mp_request smp_request;
extern volatile limine_rsdp_request rsdp_request;
extern volatile limine_tsc_frequency_request tsc_request;
}  // namespace boot

void kernel_main();
}  // namespace kernel

#endif  // KERNEL_CORE_BOOT_HPP