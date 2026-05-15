#include "core/boot.hpp"

#include "compiler.h"
#include "external/limine.h"
#include "hal/cpu.hpp"

namespace kernel {
namespace boot {
namespace {
__used __section(.limine_requests) volatile uint64_t limine_base_revision[] =
    LIMINE_BASE_REVISION(LIMINE_API_REVISION);

__used __section(.limine_requests_start) volatile uint64_t start_marker[] =
    LIMINE_REQUESTS_START_MARKER;

__used __section(.limine_requests_end) volatile uint64_t end_marker[] =
    LIMINE_REQUESTS_END_MARKER;

void verify_boot() {
  hal::cpu::disable_interrupts();
  if (!LIMINE_BASE_REVISION_SUPPORTED(limine_base_revision))
    hal::cpu::halt(false);

  hal::cpu::set_stack_pointer(boot_stack, KSTACK_SIZE, kernel_main);
}
}  // namespace

std::byte boot_stack[KSTACK_SIZE];

__used __section(
        .limine_requests
) volatile limine_entry_point_request kernel_entry_point = {
    .id       = LIMINE_ENTRY_POINT_REQUEST_ID,
    .revision = 0,
    .response = nullptr,
    .entry    = verify_boot,
};

__used __section(.limine_requests) volatile limine_hhdm_request hhdm_request = {
    .id       = LIMINE_HHDM_REQUEST_ID,
    .revision = 0,
    .response = nullptr,
};
}  // namespace boot
}  // namespace kernel