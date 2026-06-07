#include "cpu/smp.hpp"

#include <cstdint>

#include "core/logger.hpp"
#include "cpu/feats.hpp"
#include "cpu/registers.hpp"
#include "hal/smp.hpp"
#include "memory/paging/paging.hpp"
#include "memory/vm/asid.hpp"

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

PerCpuState bsp_state(CpuId{0}, NumaId{0}, ApicId{0});
log::Logger smp_log_arch{"SMP"};
}  // namespace

void initialize_cpu_hw(PerCpuState* cpu) noexcept {
  CoreState& core_state        = cpu->core_state();
  const GSBase gs_val          = {.cpu = cpu};
  const KernelGSBase kernel_gs = {.cpu = cpu};

  x86_64::cpu::write(gs_val);
  x86_64::cpu::write(kernel_gs);

  memory::AsidManager& asid_mgr = core_state.manager();
  asid_mgr.initialize(memory::arch::flush_all_pcids);

  x86_64::cpu::ProcessorState& state = cpu->processor_state();
  state.initialize();
}

PerCpuState& get_cpu_state() noexcept {
  if (unlikely(!is_initialized())) {
    static auto once = []() {
      bsp_state.processor_state().initialize();
      return true;
    }();

    return bsp_state;
  }

  auto state = x86_64::cpu::read_gs<PerCpuState*>(0);
  return *const_cast<PerCpuState*>(state->self());
}
}  // namespace smp
}  // namespace hal

x86_64::cpu::ProcessorState& x86_64::cpu::get_current_state() noexcept {
  return hal::smp::get_cpu_state().processor_state();
}
}  // namespace kernel