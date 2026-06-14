#include "hal/hal.hpp"

#include "core/log_sink.hpp"
#include "core/logger.hpp"
#include "hal/acpi.hpp"
#include "hal/smp.hpp"

namespace kernel {
namespace hal {
namespace {
log::Logger hal_logger{"HAL", log::Level::Debug};
}

void initialize() noexcept {
  if (auto result = acpi::Manager::initialize(); !result)
    hal_logger.fatal(
        "ACPI early setup failed! Status: %s",
        result.error().begin()
    );

  hal::smp::initialize();
}
}  // namespace hal
}  // namespace kernel