#include "core/boot.hpp"
#include "core/flanterm.hpp"
#include "core/log_manager.hpp"
#include "core/logger.hpp"
#include "cpu/smp.hpp"
#include "cpu/tsc.hpp"
#include "hal/hal.hpp"
#include "hal/smp.hpp"
#include "memory/memory.hpp"
#include "memory/pmm.hpp"

namespace kernel {
namespace {
log::FlantermSink flanterm;
log::Logger test{"MAIN"};
}  // namespace

void kernel_main() {
  log::LogManager::set_config(log::LogConfig{});

  flanterm.initialize();
  log::LogManager::add_sink(&flanterm);
  hal::early_init();

  memory::initialize();
  hal::initialize();

  auto res = x86_64::cpu::tsc::Clock::initialize();

  if (!res.has_value())
    test.error("Unabled to initialize TSC error: %u", res.error());

  auto ptr = memory::PhysicalManager::alloc_pages(1);

  hal::smp::PerCpuState& cpu = hal::smp::get_cpu_state();
  cpu.idle_loop();
}
}  // namespace kernel