#ifndef KERNEL_ARCH_X86_64_CPU_SMP_HPP
#define KERNEL_ARCH_X86_64_CPU_SMP_HPP 1

#include <cstdint>
#include <new>
#include <type_traits>

#include "cpu/feats.hpp"
#include "cpu/registers.hpp"
#include "hal/smp.hpp"

namespace kernel {
namespace hal {
namespace smp {
struct alignas(std::hardware_constructive_interference_size) PerCpuState final {
  PerCpuState* const self;
  CoreHotState hot;

  alignas(
      std::hardware_constructive_interference_size
  ) x86_64::cpu::ProcessorState processor_state;

  CoreColdState cold;

  constexpr PerCpuState(
      CpuId id,
      NumaId numa,
      ApicId apic,
      std::uintptr_t stack
  ) noexcept
      : self(this), hot(id, numa, apic, stack) {}

  PerCpuState(const PerCpuState&)            = delete;
  PerCpuState& operator=(const PerCpuState&) = delete;

  __nodiscard PreemptCount preempt_count() const noexcept {
    return PreemptCount{hot.preemption_count.load(std::memory_order_relaxed)};
  }

  constexpr void set_preempt_count(std::uint32_t count) noexcept {
    hot.preemption_count = count;
  }

  void preempt_disable() noexcept {
    hot.preemption_count.fetch_add(
        PreemptOffset::THREAD,
        std::memory_order_acquire
    );
  }

  void preempt_enable() noexcept {
    hot.preemption_count.fetch_sub(
        PreemptOffset::THREAD,
        std::memory_order_release
    );
  }

  void enter_hard_irq() noexcept {
    hot.preemption_count.fetch_add(
        PreemptOffset::HARD_IRQ,
        std::memory_order_acquire
    );
  }

  void exit_hard_irq() noexcept {
    hot.preemption_count.fetch_sub(
        PreemptOffset::HARD_IRQ,
        std::memory_order_release
    );
  }

  void enter_soft_irq() noexcept {
    hot.preemption_count.fetch_add(
        PreemptOffset::SOFT_IRQ,
        std::memory_order_acquire
    );
  }

  void exit_soft_irq() noexcept {
    hot.preemption_count.fetch_sub(
        PreemptOffset::SOFT_IRQ,
        std::memory_order_release
    );
  }

  void enter_nmi() noexcept {
    hot.preemption_count.fetch_add(
        PreemptOffset::NMI,
        std::memory_order_acquire
    );
  }

  void exit_nmi() noexcept {
    hot.preemption_count.fetch_sub(
        PreemptOffset::NMI,
        std::memory_order_release
    );
  }

  void send_ipi(IpiMessage msg) noexcept;
  void process_ipis() noexcept;
};

static_assert(std::is_standard_layout_v<PerCpuState>);
static_assert(offsetof(PerCpuState, self) == 0);
static_assert(offsetof(PerCpuState, hot) == 8);

void initialize_cpu_hw(PerCpuState* cpu) noexcept;
void early_bsp_initialize() noexcept;
}  // namespace smp
}  // namespace hal
}  // namespace kernel

#endif