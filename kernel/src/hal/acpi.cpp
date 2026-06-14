#include "hal/acpi.hpp"

#include <expected>
#include <string_view>

#include "libs/maths.hpp"
#include "memory/address/physical.hpp"
#include "memory/memory.hpp"
#include "memory/pmm.hpp"
#include "uacpi/status.h"
#include "uacpi/uacpi.h"

namespace kernel {
namespace hal {
namespace acpi {

std::expected<void, std::string_view> Manager::initialize() {
  const memory::PhysAddr ptr = memory::PhysicalManager::alloc_zeroed_pages(2);
  const memory::VirtAddr buffer = ptr.to_virt();

  if (!libs::maths::is_aligned(buffer.raw(), memory::PAGE_SIZE_SMALL))
    return std::unexpected(uacpi_status_to_string(UACPI_STATUS_OUT_OF_MEMORY));

  if (auto status = uacpi_setup_early_table_access(
          buffer.as<void>(),
          memory::PAGE_SIZE_SMALL * 2
      );
      status != UACPI_STATUS_OK) {
    uacpi_state_reset();
    return std::unexpected(uacpi_status_to_string(status));
  }

  return {};
}

bool Manager::is_available() noexcept {
  return uacpi_table_subsystem_available() == UACPI_TRUE;
}

std::expected<bool, std::string_view> Manager::is_reduced_hardware() {
  uacpi_bool is_reduced = UACPI_FALSE;

  if (auto status = uacpi_is_platform_reduced_hardware(&is_reduced);
      status != UACPI_STATUS_OK)
    return std::unexpected(uacpi_status_to_string(status));

  return is_reduced == UACPI_TRUE;
}

void Manager::reset() noexcept {
  uacpi_state_reset();
}
}  // namespace acpi
}  // namespace hal
}  // namespace kernel