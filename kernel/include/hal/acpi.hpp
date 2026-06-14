#include <expected>
#ifndef KERNEL_INCLUDE_HAL_ACPI_HPP
#define KERNEL_INCLUDE_HAL_ACPI_HPP 1

#include <string_view>

#include "hal/acpi/parser.hpp"
#include "hal/acpi/tables.hpp"

namespace kernel {
namespace hal {
namespace acpi {
class Manager {
 public:
  // Bootstraps the uACPI barebones table parser using early memory.
  __nodiscard static std::expected<void, std::string_view> initialize();

  // Checks if the table subsystem is successfully initialized and ready.
  __nodiscard static bool is_available() noexcept;

  // Determines if the system is running in Hardware-Reduced ACPI mode. Only
  // valid to call after initialization.
  __nodiscard static std::expected<bool, std::string_view>
  is_reduced_hardware();

  void reset() noexcept;
};
}  // namespace acpi
}  // namespace hal
}  // namespace kernel

#endif