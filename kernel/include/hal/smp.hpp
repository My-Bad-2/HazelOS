#ifndef KERNEL_HAL_SMP_HPP
#define KERNEL_HAL_SMP_HPP 1

#include <array>
#include <atomic>
#include <cstdint>
#include <new>
#include <span>

#include "compiler.h"
#include "hal/smp/ipi.hpp"
#include "memory/vm/asid.hpp"

namespace kernel {
namespace hal {
namespace smp {
enum class CpuId : std::uint32_t {};
enum class NumaId : std::uint32_t {};

namespace PreemptOffset {
constexpr std::uint32_t THREAD   = 1 << 0;
constexpr std::uint32_t SOFT_IRQ = 1 << 8;
constexpr std::uint32_t HARD_IRQ = 1 << 16;
constexpr std::uint32_t NMI      = 1 << 20;
constexpr std::uint32_t RESCHED  = 1u << 31;
}  // namespace PreemptOffset

enum class CpuActivity : std::uint8_t { Active, Idle };

union PreemptCount {
  uint32_t raw;

  struct {
    uint32_t thread_disable : 8;  // Max 255 nested locks/preempt disables
    uint32_t soft_irq       : 8;  // Max 255 nested soft IRQs
    uint32_t hard_irq       : 4;  // Max 15 nested hard IRQs
    uint32_t nmi            : 2;  // Max 3 nested NMIs
    uint32_t rsvd           : 9;
    uint32_t need_resched   : 1;  // High bit flag
  } bits;

  constexpr PreemptCount(uint32_t value = 0) noexcept : raw(value) {}

  __nodiscard constexpr bool is_preemptible() const noexcept {
    return (raw & ~PreemptOffset::RESCHED) == 0;
  }

  __nodiscard constexpr bool in_interrupt() const noexcept {
    return (bits.hard_irq > 0) || (bits.soft_irq > 0) || (bits.nmi > 0);
  }

  __nodiscard constexpr bool in_soft_interrupt() const noexcept {
    return bits.soft_irq > 0;
  }

  __nodiscard constexpr bool in_hard_interrupt() const noexcept {
    return bits.hard_irq > 0;
  }

  __nodiscard constexpr bool in_nmi() const noexcept {
    return bits.nmi > 0;
  }
};

struct CoreHotState {
  const CpuId id;
  const NumaId numa_node;
  std::atomic<std::uint32_t> preemption_count{0};

  std::uintptr_t stack_top{0};
  std::uintptr_t panic_stack_top{0};
  memory::AsidManager asid;

  std::atomic<CpuActivity> activity{CpuActivity::Active};
  std::atomic<bool> urgent_ipi_pending{false};
  std::atomic<bool> nmi_pending{false};

  ipi::IpiQueue<64> immediate_queue;
  ipi::IpiQueue<16> nmi_queue;

  constexpr CoreHotState(
      CpuId i,
      NumaId n,
      std::uintptr_t stack,
      std::uintptr_t panic_stack
  ) noexcept
      : id(i), numa_node(n), stack_top(stack), panic_stack_top(panic_stack) {}
};

struct alignas(std::hardware_constructive_interference_size) CoreColdState {
  ipi::IpiQueue<128> idle_queue;
};

class PerCpuState;

void initialize() noexcept;

const std::span<PerCpuState*> get_cpu_topology() noexcept;
PerCpuState& get_cpu_state() noexcept;
PerCpuState& get_cpu_state(std::size_t id) noexcept;
std::uint32_t get_current_core_id() noexcept;
}  // namespace smp
}  // namespace hal
}  // namespace kernel

#endif