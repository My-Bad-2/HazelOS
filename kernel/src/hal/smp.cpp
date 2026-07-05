#include "cpu/smp.hpp"

#include <atomic>
#include <cstdint>
#include <span>

#include "compiler.h"
#include "core/boot.hpp"
#include "core/logger.hpp"
#include "hal/cpu.hpp"
#include "hal/smp.hpp"
#include "libs/maths.hpp"
#include "memory/address/physical.hpp"
#include "memory/address/virtual.hpp"
#include "memory/address_space.hpp"
#include "memory/memory.hpp"
#include "memory/paging/paging.hpp"
#include "memory/pmm.hpp"

namespace kernel::hal::smp {
namespace {
log::Logger smp_logger{"SMP", log::Level::Debug};
std::atomic<bool> initialized{false};
std::uintptr_t apic_base_addr{0};

std::span<PerCpuState*> per_cpu_state;

alignas(PerCpuState) std::byte bsp_early_storage[sizeof(PerCpuState)];
PerCpuState* bsp_early_state = nullptr;

__noreturn void ap_entry_point(limine_mp_info* info) {
  PerCpuState* cpu = reinterpret_cast<PerCpuState*>(info->extra_argument);

  initialize_cpu_hw(cpu);
  memory::kernel_space->load();

  initialize_cpu_arch(cpu);

  memory::arch::initialize_cpu();
  memory::arch::initialize_pat();
  cpu->hot.asid.initialize(memory::arch::flush_all_pcids);

  smp_logger.info("APIC %u online and waiting", cpu->lapic.id());

  // Wait until the BSP finishes fully setting
  while (!initialized.load(std::memory_order_acquire)) cpu::pause();

  cpu->idle_loop();
  std::unreachable();
}
}  // namespace

void early_bsp_initialize() noexcept {
  bsp_early_state = std::construct_at(
      reinterpret_cast<PerCpuState*>(bsp_early_storage),
      CpuId{0},
      NumaId{0},
      0,
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

  const std::size_t count = libs::maths::div_roundup(
      active_cpus * sizeof(void*),
      memory::PAGE_SIZE_SMALL
  );

  PerCpuState** data = memory::PhysicalManager::alloc_zeroed_pages(count)
                           .to_virt()
                           .as<PerCpuState*>();

  per_cpu_state = std::span<PerCpuState*>{data, active_cpus};

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

    const memory::PhysAddr panic_stack_raw =
        memory::PhysicalManager::alloc_zeroed_pages(
            KSTACK_SIZE / memory::PAGE_SIZE_SMALL
        );

    if (unlikely(panic_stack_raw.is_null()))
      smp_logger.fatal(
          "Failed to allocate panic stack for CPU %u! Halting init.",
          info->lapic_id
      );

    const memory::VirtAddr panic_stack = stack_raw.to_virt();

    const memory::PhysAddr state_phys =
        memory::PhysicalManager::alloc_zeroed_pages(4);
    if (unlikely(state_phys.is_null()))
      smp_logger.fatal("Failed to allocate state for CPU %u", info->lapic_id);

    void* state_virt = reinterpret_cast<void*>(state_phys.to_virt().raw());

    PerCpuState* cpu_state = std::construct_at(
        reinterpret_cast<PerCpuState*>(state_virt),
        CpuId{i},
        NumaId{0},
        stack.raw() + KSTACK_SIZE,
        panic_stack.raw() + KSTACK_SIZE
    );

    per_cpu_state[i]     = cpu_state;
    info->extra_argument = reinterpret_cast<std::uint64_t>(cpu_state);

    if (info->lapic_id != boot::smp_request.response->bsp_lapic_id) {
      info->goto_address = ap_entry_point;
    } else {
      initialize_cpu_hw(cpu_state);
      initialize_cpu_arch(cpu_state);
      cpu_state->hot.asid.initialize(memory::arch::flush_all_pcids);

      smp_logger.info(
          "BSP (APIC %u) successfully migrated to the new state.",
          info->lapic_id
      );
    }
  }

  initialized.store(true, std::memory_order_release);
  smp_logger.info("SMP Initialized. %u cores active.", active_cpus);
}

PerCpuState& get_cpu_state(std::size_t id) noexcept {
  if (!initialized.load(std::memory_order_relaxed)) [[unlikely]]
    return *bsp_early_state;
  return *per_cpu_state[id];
}

const std::span<PerCpuState*> get_cpu_topology() noexcept {
  return per_cpu_state;
}
}  // namespace kernel::hal::smp