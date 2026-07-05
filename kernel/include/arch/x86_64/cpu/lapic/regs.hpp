#ifndef KERNEL_INCLUDE_ARCH_CPU_LAPIC_REGS_HPP
#define KERNEL_INCLUDE_ARCH_CPU_LAPIC_REGS_HPP 1

#include <cstdint>

#include "compiler.h"
#include "memory/paging/flags.hpp"

namespace kernel {
namespace x86_64 {
namespace cpu {
namespace lapic {
enum class TimerDivide : std::uint8_t {
  By2   = 0x0,
  By4   = 0x1,
  By8   = 0x2,
  By16  = 0x3,
  By32  = 0x8,
  By64  = 0x9,
  By128 = 0xa,
  By1   = 0xb
};

enum class LvtDelivery : std::uint8_t {
  FIXED  = 0,
  SMI    = 2,
  NMI    = 4,
  EXTINT = 7,
  INIT   = 5
};

enum class TimerMode : std::uint8_t {
  ONESHOT      = 0,
  PERIODIC     = 1,
  TSC_DEADLINE = 2
};

enum class IpiDelivery : std::uint8_t {
  FIXED  = 0,
  LOWEST = 1,
  SMI    = 2,
  NMI    = 4,
  INIT   = 5,
  SIPI   = 6
};

enum class IpiDestMode : std::uint8_t { PHYSICAL = 0, LOGICAL = 1 };
enum class IpiLevel : std::uint8_t { DEASSERT = 0, ASSERT = 1 };
enum class IpiTrigger : std::uint8_t { EDGE = 0, LEVEL = 1 };
enum class IpiShorthand : std::uint8_t {
  NONE               = 0,
  SELF               = 1,
  ALL_INCLUDING_SELF = 2,
  ALL_EXCLUDING_SELF = 3
};

struct HardwareErrorStatus {
 private:
  std::uint32_t raw;

 public:
  explicit constexpr HardwareErrorStatus(std::uint32_t v) : raw(v) {}

  __nodiscard constexpr bool send_cs_error() const noexcept {
    return raw & (1 << 0);
  }

  __nodiscard constexpr bool recieve_cs_error() const noexcept {
    return raw & (1 << 1);
  }

  __nodiscard constexpr bool send_accept_error() const noexcept {
    return raw & (1 << 2);
  }

  __nodiscard constexpr bool receive_accept_error() const noexcept {
    return raw & (1 << 3);
  }

  __nodiscard constexpr bool redirectable_ipi() const noexcept {
    return raw & (1 << 4);
  }

  __nodiscard constexpr bool send_illegal_vector() const noexcept {
    return raw & (1 << 5);
  }

  __nodiscard constexpr bool receive_illegal_vector() const noexcept {
    return raw & (1 << 6);
  }

  __nodiscard constexpr bool illegal_register_address() const noexcept {
    return raw & (1 << 7);
  }

  __nodiscard constexpr bool has_errors() const noexcept {
    return (raw & 0xff) != 0;
  }
};

struct IcrConfig {
 private:
  std::uint32_t m_low{0};
  std::uint32_t m_high{0};

 public:
  constexpr IcrConfig& vector(std::uint8_t vec) noexcept {
    m_low = (m_low & ~0xffu) | vec;
    return *this;
  }

  constexpr IcrConfig& delivery(IpiDelivery d) noexcept {
    m_low = (m_low & ~0x700u) | (static_cast<std::uint32_t>(d) << 8);
    return *this;
  }

  constexpr IcrConfig& dest_mode(IpiDestMode m) noexcept {
    m_low = (m_low & ~0x800u) | (static_cast<std::uint32_t>(m) << 11);
    return *this;
  }

  constexpr IcrConfig& level(IpiLevel l) noexcept {
    m_low |= (static_cast<std::uint32_t>(l) << 14);
    return *this;
  }

  constexpr IcrConfig& trigger(IpiTrigger t) noexcept {
    m_low |= (static_cast<std::uint32_t>(t) << 15);
    return *this;
  }

  constexpr IcrConfig& shorthand(IpiShorthand s) noexcept {
    m_low = (m_low & ~0xc0000u) | (static_cast<std::uint32_t>(s) << 18);
    return *this;
  }

  constexpr IcrConfig& destination(std::uint32_t dest) noexcept {
    m_high = dest;
    return *this;
  }

  constexpr IcrConfig& cluster_destination(
      std::uint16_t cluster_id,
      std::uint16_t core_mark
  ) noexcept {
    m_high = (static_cast<std::uint32_t>(cluster_id) << 16) | core_mark;
    return *this;
  }

  __nodiscard constexpr std::uint64_t to_x2apic() const noexcept {
    return (static_cast<std::uint64_t>(m_high) << 32) | m_low;
  }

  __nodiscard constexpr std::uint32_t high() const noexcept {
    return m_high;
  }

  __nodiscard constexpr std::uint32_t low() const noexcept {
    return m_low;
  }

  __nodiscard constexpr IpiDelivery get_delivery() const noexcept {
    return IpiDelivery((m_low >> 8) & 0x7);
  }
};

struct LvtConfig {
 private:
  std::uint32_t m_raw{0};

 public:
  constexpr LvtConfig& vector(std::uint8_t vec) noexcept {
    m_raw = (m_raw & ~0xffu) | vec;
    return *this;
  }

  constexpr LvtConfig& delivery(LvtDelivery d) noexcept {
    m_raw |= (static_cast<std::uint32_t>(d) << 8);
    return *this;
  }

  constexpr LvtConfig& mask(bool masked) noexcept {
    if (masked)
      m_raw |= (1 << 16);
    else
      m_raw &= ~(1u << 16);

    return *this;
  }

  constexpr LvtConfig& timer_mode(TimerMode m) noexcept {
    m_raw |= (static_cast<std::uint32_t>(m) << 17);
    return *this;
  }

  __nodiscard constexpr std::uint32_t raw() const noexcept {
    return m_raw;
  }
};

template <std::uint32_t Off>
struct ApicReg {
  static constexpr std::uint32_t OFFSET = Off;
  static constexpr std::uint32_t MSR_ID = 0x800 + (Off >> 4);

  using value_type = std::uint32_t;

  union {
    std::uint32_t raw32;
    std::uint64_t raw;
  };

  explicit ApicReg(std::uint64_t v) : raw(v) {}
};

using ID        = ApicReg<0x020>;
using VER       = ApicReg<0x030>;
using TPR       = ApicReg<0x080>;
using APR       = ApicReg<0x090>;
using PPR       = ApicReg<0x0a0>;
using EOI       = ApicReg<0x0b0>;
using RRD       = ApicReg<0x0c0>;
using LDR       = ApicReg<0x0d0>;
using DFR       = ApicReg<0x0e0>;
using SIVR      = ApicReg<0x0f0>;
using ESR       = ApicReg<0x280>;
using LVT_CMCI  = ApicReg<0x2f0>;  // Machine check corrections
using ICR_LOW   = ApicReg<0x300>;
using ICR_HIGH  = ApicReg<0x310>;
using LVT_TMR   = ApicReg<0x320>;
using LVT_TSR   = ApicReg<0x330>;
using LVT_PMC   = ApicReg<0x340>;  // Performance monitoring
using LVT_LINT0 = ApicReg<0x350>;
using LVT_LINT1 = ApicReg<0x360>;
using LVT_ERR   = ApicReg<0x370>;
using TMR_ICR   = ApicReg<0x380>;
using TMR_CCR   = ApicReg<0x390>;
using TMR_DCR   = ApicReg<0x3e0>;

struct ApicBaseMsr {
  static constexpr std::uint32_t MSR_ID = 0x1b;
  std::uint64_t raw;

  explicit ApicBaseMsr(std::uint64_t v) : raw(v) {}

  constexpr void enable_global() noexcept {
    raw |= (1u << 11);
  }

  constexpr void enable_x2apic() noexcept {
    raw |= (1 << 10);
  }

  __nodiscard constexpr std::uintptr_t get_base() const noexcept {
    return raw & memory::arch::PAGE_MASK;
  }
};

struct TscDeadlineMsr {
  static constexpr std::uint32_t MSR_ID = 0x6e0;
  std::uint64_t raw;
};

struct X2ApicIcr {
  static constexpr std::uint32_t MSR_ID = 0x830;
  std::uint64_t raw;
};

struct X2ApicSelfIpi {
  static constexpr std::uint32_t MSR_ID = 0x83f;
  std::uint64_t raw;
};
}  // namespace lapic
}  // namespace cpu
}  // namespace x86_64
}  // namespace kernel

#endif