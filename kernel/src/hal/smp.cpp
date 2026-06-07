#include "cpu/smp.hpp"

#include <cstdint>
#include <new>
#include <span>

#include "core/boot.hpp"
#include "core/logger.hpp"
#include "hal/cpu.hpp"
#include "hal/smp.hpp"
#include "memory/address_space.hpp"
#include "memory/paging/paging.hpp"

namespace kernel {
namespace hal {
namespace smp {
namespace {
struct alignas(std::hardware_constructive_interference_size) PerCpuStorage {
  alignas(PerCpuState) std::byte data[sizeof(PerCpuState)];
};

constinit std::array<PerCpuStorage, MAX_CPU_COUNT> per_cpu_storage = {};
constinit std::array<PerCpuState*, MAX_CPU_COUNT> per_cpu_state    = {};

bool initialized = false;

log::Logger smp_logger{"SMP", log::Level::Debug};

void initialize_core_state(CoreState& cpu) {
  static_cast<void>(cpu);
}

void ap_entry_point(limine_mp_info* info) {
  PerCpuState* cpu = reinterpret_cast<PerCpuState*>(info->extra_argument);

  initialize_core_state(cpu->core_state());
  initialize_cpu_hw(cpu);

  memory::arch::initialize_cpu();
  memory::arch::initialize_pat();

  memory::kernel_space->load();

  smp_logger.info("Hello From CPU %u", cpu->apic_id());

  cpu::halt(true);
}
}  // namespace

void initialize() noexcept {
  const std::span available_cpus{
      boot::smp_request.response->cpus,
      boot::smp_request.response->cpu_count
  };

  const std::uint32_t active_cpus =
      std::min<uint32_t>(available_cpus.size(), MAX_CPU_COUNT);

  for (std::uint32_t i = 0; i < active_cpus; ++i) {
    limine_mp_info* info = available_cpus[i];

    PerCpuState* cpu_state = std::construct_at(
        reinterpret_cast<PerCpuState*>(per_cpu_storage[i].data),
        CpuId{i},
        NumaId{0},
        ApicId{info->lapic_id}
    );

    per_cpu_state[i] = cpu_state;

    info->extra_argument = reinterpret_cast<std::uint64_t>(cpu_state);

    if (info->lapic_id != boot::smp_request.response->bsp_lapic_id) {
      info->goto_address = ap_entry_point;
    } else {
      initialize_core_state(cpu_state->core_state());
      initialize_cpu_hw(cpu_state);
      initialized = true;
    }
  }
}

bool is_initialized() noexcept {
  return initialized;
}

std::uint32_t get_current_core_id() noexcept {
  return std::to_underlying(get_cpu_state().core_state().id());
}

smp::CoreState& get_core_state() noexcept {
  return get_cpu_state().core_state();
}
}  // namespace smp
}  // namespace hal
}  // namespace kernel