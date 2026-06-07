#ifndef KERNEL_HAL_SMP_HPP
#define KERNEL_HAL_SMP_HPP 1

#include <atomic>
#include <cstdint>

#include "compiler.h"
#include "memory/vm/asid.hpp"

namespace kernel {
namespace hal {
namespace smp {
enum class CpuId : std::uint32_t {};
enum class NumaId : std::uint32_t {};
enum class ApicId : std::uint32_t {};

namespace PreemptOffset {
constexpr std::uint32_t THREAD   = 1 << 0;
constexpr std::uint32_t SOFT_IRQ = 1 << 8;
constexpr std::uint32_t HARD_IRQ = 1 << 16;
constexpr std::uint32_t NMI      = 1 << 20;
constexpr std::uint32_t RESCHED  = 1u << 31;
}  // namespace PreemptOffset

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

struct CoreState {
 private:
  friend class PerCpuState;
  const CpuId m_id;
  const NumaId m_numa_node;

  memory::AsidManager m_asid;
  std::atomic<std::uint32_t> m_preempt_count;

 public:
  constexpr CoreState(CpuId id, NumaId numa) noexcept
      : m_id(id), m_numa_node(numa) {}

  CoreState()                            = delete;
  CoreState(const CoreState&)            = delete;
  CoreState& operator=(const CoreState&) = delete;

  __nodiscard constexpr CpuId id() const noexcept {
    return m_id;
  }

  __nodiscard constexpr NumaId numa() const noexcept {
    return m_numa_node;
  }

  __nodiscard constexpr memory::AsidManager& manager() noexcept {
    return m_asid;
  }

  __nodiscard PreemptCount preempt_count(
      std::memory_order order = std::memory_order_relaxed
  ) const noexcept {
    return PreemptCount{m_preempt_count.load(order)};
  }

  constexpr void set_preempt_count(std::uint32_t count) noexcept {
    m_preempt_count = count;
  }

  void preempt_disable() noexcept {
    m_preempt_count.fetch_add(PreemptOffset::THREAD, std::memory_order_acquire);
  }

  void preempt_enable() noexcept {
    m_preempt_count.fetch_sub(PreemptOffset::THREAD, std::memory_order_release);
  }

  void enter_hard_irq() noexcept {
    m_preempt_count.fetch_add(
        PreemptOffset::HARD_IRQ,
        std::memory_order_acquire
    );
  }

  void exit_hard_irq() noexcept {
    m_preempt_count.fetch_sub(
        PreemptOffset::HARD_IRQ,
        std::memory_order_release
    );
  }

  void enter_soft_irq() noexcept {
    m_preempt_count.fetch_add(
        PreemptOffset::SOFT_IRQ,
        std::memory_order_acquire
    );
  }

  void exit_soft_irq() noexcept {
    m_preempt_count.fetch_sub(
        PreemptOffset::SOFT_IRQ,
        std::memory_order_release
    );
  }

  void enter_nmi() noexcept {
    m_preempt_count.fetch_add(PreemptOffset::NMI, std::memory_order_acquire);
  }

  void exit_nmit() noexcept {
    m_preempt_count.fetch_sub(PreemptOffset::NMI, std::memory_order_release);
  }
};

class PerCpuState;

void initialize() noexcept;
bool is_initialized() noexcept;

PerCpuState& get_cpu_state() noexcept;
smp::CoreState& get_core_state() noexcept;
std::uint32_t get_current_core_id() noexcept;
}  // namespace smp
}  // namespace hal
}  // namespace kernel

#endif