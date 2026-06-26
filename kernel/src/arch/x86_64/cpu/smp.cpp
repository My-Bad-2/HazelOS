#include "cpu/smp.hpp"

#include <cstdint>
#include <utility>

#include "compiler.h"
#include "core/logger.hpp"
#include "cpu/feats.hpp"
#include "cpu/registers.hpp"
#include "hal/acpi.hpp"
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

std::uintptr_t fetch_apic_address() noexcept {
  auto res = acpi::get_table<acpi::tables::Madt>("APIC");

  if (!res.has_value()) smp_log_arch.fatal("Unable to fetch MADT Table!");

  auto& madt_accessor      = res.value();
  std::uint64_t lapic_addr = madt_accessor->local_apic_address;

  for (const auto& entry : madt_accessor->subtables()) {
    if (entry.length < sizeof(acpi::SubtableHeader)) __unlikely break;

    if (entry.type == std::to_underlying(
                          acpi::tables::MadtType::LOCAL_APIC_ADDRESS_OVERRIDE
                      )) {
      auto* override_record =
          reinterpret_cast<const acpi::tables::MadtLocalApicOverride*>(&entry);

      lapic_addr = override_record->local_apic_address;
      break;
    }
  }

  return lapic_addr;
}
}  // namespace

void initialize_cpu_hw(PerCpuState* cpu) noexcept {
  const GSBase gs_val          = {.cpu = cpu};
  const KernelGSBase kernel_gs = {.cpu = cpu};

  x86_64::cpu::write(gs_val);
  x86_64::cpu::write(kernel_gs);
}

void initialize_cpu_arch(PerCpuState* cpu) noexcept {
  static std::uintptr_t lapic_address = 0;
  if (lapic_address == 0) lapic_address = fetch_apic_address();

  cpu->processor_state.initialize();

  bool has_x2apic =
      cpu->processor_state.has_feature(x86_64::cpu::CpuFeature::X2APIC);

  auto res = cpu->lapic.initialize(255, has_x2apic, lapic_address);

  if (!res.has_value())
    smp_log_arch.fatal("LAPIC initialization failed! Code: %u", res.error());
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