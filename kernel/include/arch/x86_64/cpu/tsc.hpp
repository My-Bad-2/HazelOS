#ifndef KERNEL_INCLUDE_ARCH_CPU_TSC_HPP
#define KERNEL_INCLUDE_ARCH_CPU_TSC_HPP 1

#include <cstdint>
#include <expected>

#include "compiler.h"
#include "cpu/feats.hpp"
#include "hal/smp.hpp"

namespace kernel::x86_64::cpu::tsc {
struct alignas(8) PvClockVcpuTimeInfo {
  std::uint32_t version;
  std::uint32_t pad0;
  std::uint64_t tsc_timestamp;
  std::uint64_t system_time;
  std::uint32_t tsc_to_system_mul;
  std::int8_t tsc_shift;
  std::uint8_t flags;
  std::uint16_t pad1;
};

enum class Error : std::uint8_t {
  UNSUPPORTED_ARCHITECTURE,
  NO_INVARIANT_TSC,
  DIRECT_CALIBRATION_FAILED,
  DIVISION_BY_ZERO,
  VIRTUAL_MACHINE_CALIBRATION_FAILED,
  ALREADY_INITIALIZED,
};

class Clock final {
 private:
  static std::uint64_t s_frequency_hz;
  static PvClockVcpuTimeInfo s_kvm_clock;
  static bool s_has_rdtscp;

  __nodiscard static std::expected<std::uint64_t, Error>
  intel_0x15_fallback() noexcept;

  __nodiscard static std::expected<std::uint64_t, Error> calibrate_vm(
      const HypervisorState& hypervisor
  ) noexcept;

  __nodiscard static std::expected<std::uint64_t, Error> calibrate_intel(
      const std::uint32_t max_leaf,
      const Microarchitecture uarch
  ) noexcept;

  __nodiscard static std::expected<std::uint64_t, Error> calibrate_amd(
      const Microarchitecture uarch
  ) noexcept;

  __nodiscard static std::expected<std::uint64_t, Error> calibrate_kvm(
      const HypervisorState& hypervisor
  ) noexcept;

 public:
  Clock() = delete;

  __nodiscard static std::expected<void, Error> initialize() noexcept;
  __nodiscard static std::uint64_t now(
      hal::smp::CpuId* cpu_id = nullptr
  ) noexcept;

  __nodiscard __always_inline static std::uint64_t get_frequency() noexcept {
    return s_frequency_hz;
  }

  __nodiscard static constexpr std::uint64_t seconds_to_ticks(
      std::uint64_t s
  ) noexcept {
    return s * s_frequency_hz;
  }

  __nodiscard static constexpr std::uint64_t milliseconds_to_ticks(
      std::uint64_t ms
  ) noexcept {
    return static_cast<std::uint64_t>(
        (static_cast<uint128_t>(ms) * s_frequency_hz) / 1'000ul
    );
  }

  __nodiscard static constexpr std::uint64_t microseconds_to_ticks(
      std::uint64_t us
  ) noexcept {
    return static_cast<std::uint64_t>(
        (static_cast<uint128_t>(us) * s_frequency_hz) / 1'000'000ul
    );
  }

  __nodiscard static constexpr std::uint64_t nanoseconds_to_ticks(
      std::uint64_t ns
  ) noexcept {
    return static_cast<std::uint64_t>(
        (static_cast<uint128_t>(ns) * s_frequency_hz) / 1'000'000'000ul
    );
  }

  __nodiscard static constexpr std::uint64_t ticks_to_nanoseconds(
      std::uint64_t ticks
  ) noexcept {
    return static_cast<std::uint64_t>(
        (static_cast<uint128_t>(ticks) * 1'000'000'000ul) / s_frequency_hz
    );
  }

  __nodiscard static constexpr std::uint64_t ticks_to_microseconds(
      std::uint64_t ticks
  ) noexcept {
    return static_cast<std::uint64_t>(
        (static_cast<uint128_t>(ticks) * 1'000'000ul) / s_frequency_hz
    );
  }

  __nodiscard static constexpr std::uint64_t ticks_to_milliseconds(
      std::uint64_t ticks
  ) noexcept {
    return static_cast<std::uint64_t>(
        (static_cast<uint128_t>(ticks) * 1'000ul) / s_frequency_hz
    );
  }
};
}  // namespace kernel::x86_64::cpu::tsc

#endif