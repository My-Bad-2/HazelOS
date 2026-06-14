#include "cpu/smp.hpp"

#include <cstdint>

#include "core/logger.hpp"
#include "cpu/registers.hpp"
#include "hal/smp.hpp"

namespace kernel {
namespace hal {
namespace smp {
namespace {
union GSBase {
  std::uint64_t raw;
  PerCpuState* cpu;

  static constexpr std::uint32_t MSR_ID = 0xc0000101;
};

union KernelGSBase {
  std::uint64_t raw;
  PerCpuState* cpu;

  static constexpr std::uint32_t MSR_ID = 0xc0000102;
};

PerCpuState bsp_state(CpuId{0}, NumaId{0}, ApicId{0}, 0);
log::Logger smp_log_arch{"SMP"};
}  // namespace

void initialize_cpu_hw(PerCpuState* cpu) noexcept {
  const GSBase gs_val          = {.cpu = cpu};
  const KernelGSBase kernel_gs = {.cpu = cpu};

  x86_64::cpu::write(gs_val);
  x86_64::cpu::write(kernel_gs);
}

PerCpuState& get_cpu_state() noexcept {
  auto state = x86_64::cpu::read_gs<PerCpuState*>(0);
  return *state;
}

std::uint32_t get_current_core_id() noexcept {
  return std::to_underlying(get_cpu_state().hot.id);
}
}  // namespace smp
}  // namespace hal
}  // namespace kernel