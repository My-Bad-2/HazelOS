#include "core/boot.hpp"
#include "core/flanterm.hpp"
#include "core/log_manager.hpp"
#include "core/logger.hpp"
#include "hal/cpu.hpp"
#include "hal/hal.hpp"

namespace kernel {
namespace {
log::FlantermSink flanterm;
}

void kernel_main() {
  hal::early_init();

  flanterm.initialize();
  log::LogManager::add_sink(&flanterm);

  log::LogManager::set_config(log::LogConfig{});
  const log::Logger test{"TEST"};

  test.info("Hello, World!");

  hal::cpu::halt(false);
}
}  // namespace kernel