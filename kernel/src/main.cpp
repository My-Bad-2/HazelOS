#include "core/boot.hpp"
#include "core/flanterm.hpp"
#include "core/log_manager.hpp"
#include "core/logger.hpp"
#include "hal/cpu.hpp"
#include "hal/hal.hpp"
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

  auto ptr = memory::PhysicalManager::alloc_pages(1);

  test.info("Hello, World!");

  hal::cpu::halt(false);
}
}  // namespace kernel