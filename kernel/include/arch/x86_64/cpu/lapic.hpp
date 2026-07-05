#ifndef KERNEL_INCLUDE_ARCH_X86_64_CPU_LAPIC_HPP
#define KERNEL_INCLUDE_ARCH_X86_64_CPU_LAPIC_HPP 1

#include <cstdint>
#include <expected>

#include "compiler.h"
#include "cpu/lapic/regs.hpp"
#include "cpu/registers.hpp"
#include "libs/mmio.hpp"
#include "locks.hpp"

namespace kernel {
namespace x86_64 {
namespace cpu {
namespace lapic {
enum class ApicError : std::uint8_t {
  InvalidVector,
  HardwareFault,
  InvalidTimerMode,
  IpiDeliveryTimeout,
  IpiPreempted
};

class LocalApic {
 private:
  std::uintptr_t m_xapic_base{0xfee00000};

  std::uint32_t m_suspend_tmr{0};
  std::uint32_t m_suspend_pmc{0};
  std::uint32_t m_suspend_lint0{0};
  std::uint32_t m_suspend_lint1{0};
  std::uint32_t m_suspend_err{0};
  std::uint32_t m_suspend_cmci{0};
  std::uint32_t m_suspend_sivr{0};
  std::uint32_t m_cached_id{0};

  std::uint8_t m_max_lvt_entries{0};
  bool m_is_x2apic{false};

  mutable SpinLock m_xapic_icr_lock;

  template <typename Reg>
  __nodiscard inline Reg read() const noexcept {
    if (m_is_x2apic) [[likely]]
      return x86_64::cpu::read<Reg>();

    return libs::mmio::read<Reg>(
        reinterpret_cast<volatile void*>(m_xapic_base)
    );
  }

  template <typename Reg>
  inline void write(Reg val) const noexcept {
    if (m_is_x2apic) [[likely]]
      x86_64::cpu::write<Reg>(val);
    else
      libs::mmio::write(reinterpret_cast<volatile void*>(m_xapic_base), val);
  }

 public:
  LocalApic() = default;

  std::expected<void, ApicError>
  initialize(std::uint8_t spurious_vec, bool enable_x2apic) noexcept;

  void send_eoi() const noexcept;

  __nodiscard inline std::uint8_t lvt_count() const noexcept {
    return m_max_lvt_entries;
  }

  __nodiscard inline std::uint32_t id() const noexcept {
    return m_cached_id;
  }

  __nodiscard inline std::uint16_t cluster_id() const noexcept {
    if (m_is_x2apic) [[likely]]
      return static_cast<std::uint16_t>(m_cached_id >> 4);

    return static_cast<std::uint16_t>((m_cached_id >> 2) & 0x0fu);
  }

  __nodiscard inline std::uint16_t core_mask() const noexcept {
    if (m_is_x2apic) [[likely]]
      return static_cast<std::uint16_t>(1 << (m_cached_id & 0x0fu));

    return static_cast<std::uint16_t>(1 << (m_cached_id & 0x03u));
  }

  std::expected<void, ApicError> arm_periodic(
      std::uint8_t vector,
      std::uint32_t ticks,
      TimerDivide div
  ) noexcept;

  std::expected<void, ApicError>
  arm_tsc_deadline(std::uint8_t vector, std::uint64_t absolute_tsc) noexcept;

  // Power Management
  void suspend() noexcept;
  void resume() noexcept;

  void setup_nmi(bool on_lint1 = true) noexcept;
  std::expected<void, ApicError> setup_profiler(std::uint8_t vector) noexcept;
  std::expected<void, ApicError> setup_cmci(std::uint8_t vector) noexcept;

  __always_inline void set_task_priority(std::uint8_t priority_class) noexcept {
    CR8 cr8{
        .bits = {
            .priority = priority_class,
            .reserved = 0,
        },
    };
    return x86_64::cpu::write(cr8);
  }

  __always_inline std::uint8_t get_task_priority() const noexcept {
    // Returns value between 0 and 15
    return x86_64::cpu::read<CR8>().bits.priority;
  }

  HardwareErrorStatus read_hardware_errors() const noexcept;

  // IPI
  std::expected<void, ApicError>
  send_ipi(const IcrConfig& config, bool is_nmi_context = false) const noexcept;

  std::expected<void, ApicError>
  broadcast_ipi(std::uint8_t vector, bool include_self = false) noexcept;

  std::expected<void, ApicError> broadcast_multicast_ipi(
      std::uint16_t cluster_id,
      std::uint16_t core_mask,
      std::uint8_t vector
  ) const noexcept;

  void send_self_ipi(std::uint8_t vector) const noexcept;
};
}  // namespace lapic
}  // namespace cpu
}  // namespace x86_64
}  // namespace kernel

#endif