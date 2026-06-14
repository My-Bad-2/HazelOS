#include "locks.hpp"

#include <atomic>
#include <cstdint>
#include <utility>

#include "cpu/smp.hpp"
#include "hal/cpu.hpp"
#include "hal/smp.hpp"

namespace kernel {
namespace {
MCSNode g_cpu_queue_nodes[MAX_CPU_COUNT];

constexpr std::uint32_t
encode_node_indx(std::uint32_t cpu_id, std::uint32_t nesting) noexcept {
  return (cpu_id * MAX_NESTING_LEVEL) + nesting + 1;
}

constexpr std::atomic<std::uint32_t>& get_node_state(
    std::uint32_t index
) noexcept {
  const std::uint32_t flat = index - 1;
  return g_cpu_queue_nodes[flat / MAX_NESTING_LEVEL]
      .state[flat % MAX_NESTING_LEVEL];
}

constexpr std::uint32_t get_nesting_lvl(hal::smp::PreemptCount preempt_count) {
  if (preempt_count.in_nmi()) return 3;
  if (preempt_count.in_hard_interrupt()) return 2;
  if (preempt_count.in_soft_interrupt()) return 1;
  return 0;
}
}  // namespace

void MCSLock::lock() {
  using namespace hal::smp;
  const PerCpuState& core         = get_cpu_state();
  const std::uint32_t core_id     = std::to_underlying(core.hot.id);
  const std::uint32_t nesting_lvl = get_nesting_lvl(core.preempt_count());

  const std::uint32_t curr_idx = encode_node_indx(core_id, nesting_lvl);
  std::uint32_t expected_tail  = 0;

  // If the tail is 0, atomically insert the current index
  if (m_tail.compare_exchange_strong(
          expected_tail,
          curr_idx,
          std::memory_order_acquire,
          std::memory_order_relaxed
      ))
    return;

  std::atomic<std::uint32_t>& curr_state = get_node_state(curr_idx);

  // Set waiting
  curr_state.store(1, std::memory_order_relaxed);

  // Link current index into the predecessor
  const std::uint32_t prev_idx =
      m_tail.exchange(curr_idx, std::memory_order_acq_rel);
  get_node_state(prev_idx).fetch_or(curr_idx << 1, std::memory_order_release);

  while (curr_state.load(std::memory_order_acquire) & 1) hal::cpu::pause();
}

void MCSLock::unlock() {
  using namespace hal::smp;
  const PerCpuState& core         = get_cpu_state();
  const std::uint32_t core_id     = std::to_underlying(core.hot.id);
  const std::uint32_t nesting_lvl = get_nesting_lvl(core.preempt_count());

  const std::uint32_t curr_idx = encode_node_indx(core_id, nesting_lvl);
  std::atomic<std::uint32_t>& curr_state = get_node_state(curr_idx);

  std::uint32_t state    = curr_state.load(std::memory_order_relaxed);
  std::uint32_t next_idx = curr_state >> 1;

  if (next_idx == 0) {
    std::uint32_t expected_tail = curr_idx;
    if (m_tail.compare_exchange_strong(
            expected_tail,
            0,
            std::memory_order_release,
            std::memory_order_relaxed
        ))
      return;

    while (((state = curr_state.load(std::memory_order_acquire)) >> 1) == 0)
      hal::cpu::pause();

    next_idx = state >> 1;
  }

  curr_state.store(0, std::memory_order_relaxed);
  get_node_state(next_idx).fetch_and(~1u, std::memory_order_release);
}
}  // namespace kernel