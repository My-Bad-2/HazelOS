#ifndef KERNEL_ARCH_X86_64_CPU_SMP_HPP
#define KERNEL_ARCH_X86_64_CPU_SMP_HPP 1

#include <cstdint>
#include <new>
#include <type_traits>

#include "cpu/feats.hpp"
#include "cpu/gdt.hpp"
#include "cpu/lapic.hpp"
#include "hal/smp.hpp"
#include "hal/smp/ipi.hpp"

namespace kernel::hal::smp {
struct alignas(std::hardware_constructive_interference_size) PerCpuState final {
  PerCpuState* const self;
  x86_64::cpu::lapic::LocalApic lapic;
  CoreHotState hot;

  x86_64::cpu::ProcessorState processor_state;
  x86_64::cpu::gdt::DescriptorTable gdt;

  CoreColdState cold;

  constexpr PerCpuState(
      CpuId id,
      NumaId numa,
      std::uintptr_t stack,
      std::uintptr_t panic_stack
  ) noexcept
      : self(this), hot(id, numa, stack, panic_stack), gdt() {}

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

  void send_ipi(const ipi::Message& msg) noexcept;
  void process_ipis() noexcept;
  void process_nmis() noexcept;
  void idle_loop() noexcept;
  void panic_sync() noexcept;
};

static_assert(std::is_standard_layout_v<PerCpuState>);
static_assert(offsetof(PerCpuState, self) == 0);

void initialize_cpu_hw(PerCpuState* cpu) noexcept;
void initialize_cpu_arch(PerCpuState* cpu) noexcept;
void early_bsp_initialize() noexcept;
}  // namespace kernel::hal::smp

#endif