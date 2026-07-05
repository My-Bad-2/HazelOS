#include "cpu/smp.hpp"

#include <cstdint>
#include <utility>

#include "core/logger.hpp"
#include "cpu/feats.hpp"
#include "cpu/interrupts.hpp"
#include "cpu/interrupts/common.hpp"
#include "cpu/interrupts/idt.hpp"
#include "cpu/registers.hpp"
#include "hal/smp.hpp"

namespace kernel::hal::smp {
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

log::Logger smp_log_arch{"SMP"};

struct TscAuxMsr {
  std::uint64_t raw;
  static constexpr std::uint32_t MSR_ID = 0xC0000103;

  constexpr explicit TscAuxMsr(std::uint64_t val) noexcept : raw(val) {}

  __nodiscard static constexpr TscAuxMsr create(CpuId core_id, NumaId numa) {
    return TscAuxMsr(
        (static_cast<std::uint64_t>(numa) << 32) |
        static_cast<std::uint32_t>(core_id)
    );
  }

  __nodiscard constexpr CpuId get_core_id() const noexcept {
    return static_cast<CpuId>(raw & 0xffffffff);
  }
};

struct X2ApicLDR {
  std::uint32_t raw;
  constexpr static std::uint32_t MSR_ID = 0x80d;

  constexpr explicit X2ApicLDR(std::uint32_t v) : raw(v) {}

  constexpr std::uint16_t cluster_id() const noexcept {
    return (raw >> 16) & 0xffff;
  }

  constexpr std::uint16_t logical_id() const noexcept {
    return static_cast<std::uint16_t>(raw);
  }
};

extern "C" const std::uintptr_t isr_stub_table[256];
extern "C" void* fred_entry_page;

void populate_idt(x86_64::cpu::interrupts::idt::Table<256>& table) noexcept {
  using namespace x86_64::cpu::interrupts;
  constexpr std::uint16_t KERNEL_CS = 0x08;

  for (std::size_t i = 0; i < 256; ++i) {
    auto handler = reinterpret_cast<void (*)()>(isr_stub_table[i]);

    if ((i == InterruptVectors::NMI) || (i == InterruptVectors::DOUBLE_FAULT) ||
        (i == InterruptVectors::MACHINE_CHECK)) {
      table.set_handler(
          i,
          handler,
          KERNEL_CS,
          idt::GateType::Interrupt,
          PrivilegeLevel::RING0,
          idt::IstIndex::IST1
      );
    } else {
      table.set_handler(i, handler, KERNEL_CS);
    }
  }
}

x86_64::cpu::interrupts::idt::Table<256> global_idt;
}  // namespace

void initialize_cpu_hw(PerCpuState* cpu) noexcept {
  const GSBase gs_val          = {.cpu = cpu};
  const KernelGSBase kernel_gs = {.cpu = cpu};

  x86_64::cpu::write(gs_val);
  x86_64::cpu::write(kernel_gs);

  TscAuxMsr msr = TscAuxMsr::create(cpu->hot.id, cpu->hot.numa_node);
  x86_64::cpu::write(msr);
}

void initialize_cpu_arch(PerCpuState* cpu) noexcept {
  using namespace x86_64::cpu::interrupts;

  cpu->processor_state.initialize();
  cpu->gdt.load(cpu->hot.stack_top, cpu->hot.panic_stack_top);

  static bool once = []() {
    populate_idt(global_idt);
    return true;
  }();

  fred::FRED_STKLVLS stklvls{0};

  stklvls.bits.nmi           = 1;
  stklvls.bits.double_fault  = 1;
  stklvls.bits.machine_check = 1;

  EventConfig config{fred_entry_page, stklvls, global_idt};

  auto delivery_res = DeliveryManager::initialize(config);

  if (!delivery_res)
    smp_log_arch.fatal(
        "Failed to initialize Interrupts! Code: %u",
        delivery_res.error()
    );

  bool has_x2apic =
      cpu->processor_state.has_feature(x86_64::cpu::CpuFeature::X2APIC);

  auto res = cpu->lapic.initialize(
      x86_64::cpu::interrupts::InterruptVectors::APIC_SPURIOUS_INT,
      has_x2apic
  );

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
}  // namespace kernel::hal::smp