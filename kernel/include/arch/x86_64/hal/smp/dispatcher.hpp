#ifndef KERNEL_INCLUDE_ARCH_HAL_SMP_DISPATCHER_HPP
#define KERNEL_INCLUDE_ARCH_HAL_SMP_DISPATCHER_HPP 1

#include <cstdint>
#include <span>

#include "compiler.h"
#include "cpu/lapic.hpp"
#include "hal/cpu.hpp"
#include "hal/smp/ipi.hpp"

namespace kernel::hal::smp {
struct PerCpuState;
}

namespace kernel::hal::smp::ipi {
class Dispatcher final {
 private:
  template <std::size_t Cap>
  static void enqueue(IpiQueue<Cap>& queue, const Message& msg) noexcept {
    std::uint32_t backoff = 1;

    while (!queue.push(msg)) [[unlikely]] {
      for (std::uint32_t i = 0; i < backoff; ++i) cpu::pause();

      if (backoff < 64) backoff <<= 1;
    }
  }

  template <std::size_t Cap>
  static void
  enqueue(IpiQueue<Cap>& queue, std::span<const Message> msgs) noexcept {
    std::uint32_t backoff = 1;

    while (!queue.push_batch(msgs)) [[unlikely]] {
      for (std::uint32_t i = 0; i < backoff; ++i) cpu::pause();

      if (backoff < 64) backoff <<= 1;
    }
  }

  static void trigger(
      PerCpuState& target,
      x86_64::cpu::lapic::IcrConfig icr,
      bool is_nmi = false
  ) noexcept;

 public:
  Dispatcher() = delete;

  static void send(PerCpuState& target, std::span<const Message> msgs) noexcept;
  static void
  send_nmi(PerCpuState& target, std::span<const Message> msgs) noexcept;
  static void send_self(std::span<const Message> msgs) noexcept;
  static void broadcast(
      std::span<PerCpuState*> all_cpus,
      std::span<const Message> msgs,
      bool include_self
  ) noexcept;
  static void multicast(
      std::span<PerCpuState*> all_cpus,
      std::uint16_t cluster_id,
      std::uint16_t core_mask,
      std::span<const Message> msgs
  ) noexcept;
};
}  // namespace kernel::hal::smp::ipi

#endif