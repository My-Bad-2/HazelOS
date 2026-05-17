#include "hal/hal.hpp"

#include "core/log_manager.hpp"
#include "core/log_sink.hpp"
#include "core/uart.hpp"
#include "cpu/feats.hpp"

namespace kernel {
namespace hal {
namespace {
x86_64::UartSink uart;
}

void early_init() noexcept {
  x86_64::cpu::g_bsp_state.initialize();

  uart.initialize();
  uart.set_level(log::Level::Error);

  log::LogManager::add_sink(&uart);
}
}  // namespace hal
}  // namespace kernel