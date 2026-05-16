#ifndef KERNEL_CORE_BOOT_HPP
#define KERNEL_CORE_BOOT_HPP 1

#include <cstddef>

#include "external/limine.h"

namespace kernel {
namespace boot {
extern std::byte boot_stack[];
extern volatile limine_entry_point_request kernel_entry_point;
extern volatile limine_hhdm_request hhdm_request;
extern volatile limine_framebuffer_request framebuffer_request;
}  // namespace boot

void kernel_main();
}  // namespace kernel

#endif  // KERNEL_CORE_BOOT_HPP