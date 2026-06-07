#include "core/boot.hpp"
#include "core/flanterm.hpp"
#include "core/log_manager.hpp"
#include "core/logger.hpp"
#include "hal/cpu.hpp"
#include "hal/hal.hpp"
#include "hal/smp.hpp"
#include "libs/maths.hpp"
#include "memory/memory.hpp"
#include "memory/pmm.hpp"

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

  memory::initialize();
  hal::smp::initialize();

  auto ptr = memory::PhysicalManager::alloc_pages(1);

  test.info("ptr = 0x%lx", ptr.raw());

  using namespace libs::maths::literals;

  auto a = 1.5_KiB;
  test.info("a = %lu", a);

  test.info("Hello, World!");

  hal::cpu::halt(false);
}
}  // namespace kernel