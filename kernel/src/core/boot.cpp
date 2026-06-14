#include "core/boot.hpp"

#include "compiler.h"
#include "external/limine.h"
#include "hal/cpu.hpp"
#include "support/cxxabi.hpp"

namespace kernel {
namespace boot {
namespace {
static std::byte boot_stack[KSTACK_SIZE];
std::uintptr_t hhdm_offset = 0;

__used __section(.limine_requests) volatile uint64_t limine_base_revision[] =
    LIMINE_BASE_REVISION(LIMINE_API_REVISION);

__used __section(.limine_requests_start) volatile uint64_t start_marker[] =
    LIMINE_REQUESTS_START_MARKER;

__used __section(.limine_requests_end) volatile uint64_t end_marker[] =
    LIMINE_REQUESTS_END_MARKER;

void verify_boot() {
  support::call_global_ctor();
  hal::cpu::disable_interrupts();
  if (!LIMINE_BASE_REVISION_SUPPORTED(limine_base_revision))
    hal::cpu::halt(false);

  hhdm_offset = hhdm_request.response->offset;

  hal::cpu::set_stack_pointer(boot_stack, KSTACK_SIZE, kernel_main);
  support::call_global_dtor();
}
}  // namespace

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

__used __section(
        .limine_requests
) volatile limine_framebuffer_request framebuffer_request = {
    .id       = LIMINE_FRAMEBUFFER_REQUEST_ID,
    .revision = 1,
    .response = nullptr,
};

__used __section(
        .limine_requests
) volatile limine_memmap_request memmap_request = {
    .id       = LIMINE_MEMMAP_REQUEST_ID,
    .revision = 0,
    .response = nullptr,
};

__used __section(
        .limine_requests
) volatile limine_executable_address_request kernel_addr_request = {
    .id       = LIMINE_EXECUTABLE_ADDRESS_REQUEST_ID,
    .revision = 0,
    .response = nullptr,
};

__used __section(.limine_requests) volatile limine_mp_request smp_request{
    .id       = LIMINE_MP_REQUEST_ID,
    .revision = 1,
    .response = nullptr,
#ifdef __x86_64__
    .flags = LIMINE_MP_RESPONSE_X86_64_X2APIC,
#endif
};

__used __section(.limine_requests) volatile limine_rsdp_request rsdp_request{
    .id       = LIMINE_RSDP_REQUEST_ID,
    .revision = 0,
    .response = nullptr,
};

std::uintptr_t get_hhdm_offset() noexcept {
  return hhdm_offset;
}
}  // namespace boot
}  // namespace kernel