#include "cpu/smp.hpp"

#include <atomic>
#include <cstdint>
#include <span>

#include "compiler.h"
#include "core/boot.hpp"
#include "core/logger.hpp"
#include "hal/cpu.hpp"
#include "memory/address/physical.hpp"
#include "memory/address/virtual.hpp"
#include "memory/address_space.hpp"
#include "memory/memory.hpp"
#include "memory/paging/paging.hpp"
#include "memory/pmm.hpp"

namespace kernel {
namespace hal {
namespace smp {
namespace {
log::Logger smp_logger{"SMP", log::Level::Debug};
std::atomic<bool> initialized{false};

constinit std::array<PerCpuState*, MAX_CPU_COUNT> per_cpu_state = {};

alignas(PerCpuState) std::byte bsp_early_storage[sizeof(PerCpuState)];
PerCpuState* bsp_early_state = nullptr;

__noreturn void ap_entry_point(limine_mp_info* info) {
  PerCpuState* cpu = reinterpret_cast<PerCpuState*>(info->extra_argument);

  initialize_cpu_hw(cpu);
  memory::kernel_space->load();

  memory::arch::initialize_cpu();
  memory::arch::initialize_pat();
  cpu->processor_state.initialize();
  cpu->hot.asid.initialize(memory::arch::flush_all_pcids);

  smp_logger.info("APIC %u online and waiting", cpu->hot.apic_id);

  // Wait until the BSP finishes fully setting
  while (!initialized.load(std::memory_order_acquire)) cpu::pause();

  cpu::halt(true);
  std::unreachable();
}
}  // namespace

void early_bsp_initialize() noexcept {
  bsp_early_state = std::construct_at(
      reinterpret_cast<PerCpuState*>(bsp_early_storage),
      CpuId{0},
      NumaId{0},
      ApicId{0},
      0
  );

  initialize_cpu_hw(bsp_early_state);
  bsp_early_state->processor_state.initialize();
}

void initialize() noexcept {
  const std::span available_cpus{
      boot::smp_request.response->cpus,
      boot::smp_request.response->cpu_count
  };

  const std::uint32_t active_cpus =
      std::min<uint32_t>(available_cpus.size(), MAX_CPU_COUNT);

  for (std::uint32_t i = 0; i < active_cpus; ++i) {
    limine_mp_info* info = available_cpus[i];

    const memory::PhysAddr stack_raw =
        memory::PhysicalManager::alloc_zeroed_pages(
            KSTACK_SIZE / memory::PAGE_SIZE_SMALL
        );

    if (unlikely(stack_raw.is_null()))
      smp_logger.fatal(
          "Failed to allocate stack for CPU %u! Halting init.",
          info->lapic_id
      );

    const memory::VirtAddr stack = stack_raw.to_virt();

    const memory::PhysAddr state_phys =
        memory::PhysicalManager::alloc_zeroed_pages(1);
    if (unlikely(state_phys.is_null()))
      smp_logger.fatal("Failed to allocate state for CPU %u", info->lapic_id);

    void* state_virt = reinterpret_cast<void*>(state_phys.to_virt().raw());

    PerCpuState* cpu_state = std::construct_at(
        reinterpret_cast<PerCpuState*>(state_virt),
        CpuId{i},
        NumaId{0},
        ApicId{info->lapic_id},
        stack.raw() + KSTACK_SIZE
    );

    per_cpu_state[i]     = cpu_state;
    info->extra_argument = reinterpret_cast<std::uint64_t>(cpu_state);

    if (info->lapic_id != boot::smp_request.response->bsp_lapic_id) {
      info->goto_address = ap_entry_point;
    } else {
      initialize_cpu_hw(cpu_state);
      cpu_state->processor_state.initialize();
      smp_logger.info(
          "BSP (APIC %u) successfully migrated to the new state.",
          info->lapic_id
      );
    }
  }

  initialized.store(true, std::memory_order_release);
  smp_logger.info("SMP Initialized. %u cores active.", active_cpus);
}
}  // namespace smp
}  // namespace hal
}  // namespace kernel