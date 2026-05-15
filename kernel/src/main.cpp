#include "core/boot.hpp"
#include "core/log_sink.hpp"
#include "hal/cpu.hpp"

void kernel::kernel_main() {
  hal::cpu::halt(false);
}