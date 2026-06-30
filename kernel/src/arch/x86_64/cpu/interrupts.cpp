#include "cpu/interrupts.hpp"

#include <expected>

#include "cpu/feats.hpp"
#include "cpu/interrupts/common.hpp"
#include "cpu/registers.hpp"

namespace kernel::x86_64::cpu::interrupts {
std::expected<ActiveMode, InterruptErrors> DeliveryManager::initialize(
    const EventConfig& config
) noexcept {
  ProcessorState& state = get_current_state();
  if (state.has_feature(CpuFeature::FRED)) {
    fred::FRED_CONFIG fred_cfg{};

    if (!fred_cfg.set_entry_page(config.fred_entry_page))
      return std::unexpected(InterruptErrors::FRED_MISALIGNED_ENTRYPOINT);

    write(config.fred_stack_levels);
    write(fred_cfg);

    auto cr4      = read<CR4>();
    cr4.bits.fred = 1;
    write(cr4);

    return ActiveMode::FRED;
  }

  config.idt.load();
  return ActiveMode::IDT;
}
}  // namespace kernel::x86_64::cpu::interrupts