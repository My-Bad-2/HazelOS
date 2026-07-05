#include "cpu/tsc.hpp"

#include <cstdint>
#include <expected>

#include "compiler.h"
#include "core/boot.hpp"
#include "core/log_sink.hpp"
#include "core/logger.hpp"
#include "cpu/feats.hpp"
#include "cpu/registers.hpp"
#include "memory/address/physical.hpp"
#include "memory/address/virtual.hpp"
#include "memory/address_space.hpp"

namespace kernel::x86_64::cpu::tsc {
namespace {
struct HvTscFreq {
  std::uint64_t raw;
  constexpr static std::uint32_t MSR_ID = 0x40000022;

  HvTscFreq(std::uint64_t v) : raw(v) {}

  constexpr std::uint64_t frequency() const noexcept {
    return raw;
  }
};

struct IntelPlatformInfoMsr {
  std::uint64_t raw;
  static constexpr std::uint32_t MSR_ID = 0x000000CE;

  constexpr explicit IntelPlatformInfoMsr(std::uint64_t val) noexcept
      : raw(val) {}

  __nodiscard constexpr std::uint64_t get_max_non_turbo_ratio() const noexcept {
    return (raw >> 8) & 0xFF;
  }
};

struct AmdLegacyPstateMsr {
  std::uint64_t raw;
  static constexpr std::uint32_t MSR_ID = 0xC0010064;

  constexpr explicit AmdLegacyPstateMsr(std::uint64_t val) noexcept
      : raw(val) {}

  __nodiscard constexpr bool is_valid() const noexcept {
    return (raw & (1ULL << 63)) != 0;
  }

  // CPU Frequency ID
  __nodiscard constexpr std::uint64_t get_fid() const noexcept {
    return raw & 0x3F;
  }

  // CPU Divisor ID
  __nodiscard constexpr std::uint64_t get_did() const noexcept {
    return (raw >> 6) & 0x07;
  }
};

struct AmdZenPstateMsr {
  std::uint64_t raw;
  static constexpr std::uint32_t MSR_ID = 0xC0010064;

  constexpr explicit AmdZenPstateMsr(std::uint64_t val) noexcept : raw(val) {}

  __nodiscard constexpr bool is_valid() const noexcept {
    return (raw & (1ul << 63)) != 0;
  }

  // Core Frequency ID
  __nodiscard constexpr std::uint64_t get_fid() const noexcept {
    return raw & 0xff;
  }

  // Core Divisor ID
  __nodiscard constexpr std::uint64_t get_did() const noexcept {
    return (raw >> 8) & 0x3f;
  }
};

struct KvmClock {
  std::uint64_t raw;

  static constexpr std::uint32_t MSR_ID = 0x4B564D01;
  KvmClock(std::uint64_t v) : raw(v) {}
};

log::Logger tsc_logger{"TSC", log::Level::Debug};
}  // namespace

std::uint64_t Clock::s_frequency_hz = 0;
PvClockVcpuTimeInfo Clock::s_kvm_clock{};
bool Clock::s_has_rdtscp = false;

std::expected<std::uint64_t, Error> Clock::intel_0x15_fallback() noexcept {
  CpuidRegs timing = ProcessorState::call_cpuid(0x15, 0);

  // TSC Freq = ECX * (EBX / EAX)
  if (timing.eax != 0 && timing.ebx != 0 && timing.ecx != 0)
    return (static_cast<std::uint64_t>(timing.ecx) * timing.ebx) / timing.eax;

  return std::unexpected(Error::DIRECT_CALIBRATION_FAILED);
}

std::expected<std::uint64_t, Error> Clock::calibrate_kvm(
    const HypervisorState& hypervisor
) noexcept {
  if (!hypervisor.has_kvm_feature(KvmFeature::CLOCK_SOURCE2))
    return std::unexpected(Error::VIRTUAL_MACHINE_CALIBRATION_FAILED);

  const memory::VirtAddr virt_addr{
      reinterpret_cast<std::uint64_t>(&s_kvm_clock)
  };
  const memory::PhysAddr phys_addr = memory::kernel_space->resolve(virt_addr);

  auto clock = read<KvmClock>();
  clock.raw  = phys_addr.raw() | 1;  // set bit 0 to enable the clock
  write(clock);

  asm volatile("lfence" ::: "memory");

  const std::uint32_t mul = s_kvm_clock.tsc_to_system_mul;
  const std::int8_t shift = s_kvm_clock.tsc_shift;

  // Disable the clock
  clock.raw = 0;
  write(clock);

  if (mul == 0) return std::unexpected(Error::DIVISION_BY_ZERO);

  // KVM: ns = (tsc * 2^shift * mul) >> 32
  // => 1 sec (10^9 ns) = (freq * 2^shift * mul) >> 32
  std::uint64_t base_freq = (1'000'000'000ul << 32) / mul;

  if (shift > 0)
    return base_freq >> shift;
  else if (shift < 0)
    return base_freq << -shift;
  return base_freq;
}

std::expected<std::uint64_t, Error> Clock::calibrate_vm(
    const HypervisorState& hypervisor
) noexcept {
  if (hypervisor.vendor == HypervisorVendor::KVM) {
    auto kvm_freq = calibrate_kvm(hypervisor);

    if (kvm_freq.has_value()) return kvm_freq.value();
  } else if (hypervisor.vendor == HypervisorVendor::VMWARE) {
    if (hypervisor.max_leaf >= 0x40000010) {
      CpuidRegs regs = ProcessorState::call_cpuid(0x40000010, 0);

      if (regs.eax != 0) return static_cast<std::uint64_t>(regs.eax) * 1000ul;
    }
  } else if (hypervisor.vendor == HypervisorVendor::HYPERV) {
    if (!hypervisor.has_hyperv_feature(HyperVFeature::TIME_REFERENCE_COUNT))
      return std::unexpected(Error::VIRTUAL_MACHINE_CALIBRATION_FAILED);

    auto msr                 = read<HvTscFreq>();
    const std::uint64_t freq = msr.frequency();
    if (freq != 0) return freq;
  }

  // Fall back to emulated Intel Leaf 0x15
  return intel_0x15_fallback();
}

std::expected<std::uint64_t, Error> Clock::calibrate_intel(
    const std::uint32_t max_leaf,
    const Microarchitecture uarch
) noexcept {
  if (max_leaf >= 0x15) {
    auto res = intel_0x15_fallback();

    if (res.has_value()) return res;
  }

  // Skylake / Kaby Lake uses Leaf 0x16 as fallback
  if (max_leaf >= 0x16) {
    CpuidRegs info = ProcessorState::call_cpuid(0x16, 0);

    if (info.eax != 0)
      return static_cast<std::uint64_t>(info.eax) * 1'000'000ul;
  }

  // Uses rigid 133.333 MHz Base Clock
  if (uarch == Microarchitecture::INTEL_NEHALEM ||
      uarch == Microarchitecture::INTEL_WESTMERE) {
    auto msr                  = read<IntelPlatformInfoMsr>();
    const std::uint64_t ratio = msr.get_max_non_turbo_ratio();

    if (ratio != 0) return ratio * 133'333'333ul;
  }

  // Uses rigid 100.000 MHz Base Clock
  if (uarch >= Microarchitecture::INTEL_SANDY_BRIDGE &&
      uarch <= Microarchitecture::INTEL_BROADWELL) {
    auto msr                  = read<IntelPlatformInfoMsr>();
    const std::uint64_t ratio = msr.get_max_non_turbo_ratio();

    if (ratio != 0) return ratio * 100'000'000ul;
  }

  return std::unexpected(Error::DIRECT_CALIBRATION_FAILED);
}

std::expected<std::uint64_t, Error> Clock::calibrate_amd(
    const Microarchitecture uarch
) noexcept {
  if (uarch >= Microarchitecture::AMD_ZEN1 &&
      uarch <= Microarchitecture::AMD_ZEN5) {
    auto msr = read<AmdZenPstateMsr>();

    if (!msr.is_valid())
      return std::unexpected(Error::DIRECT_CALIBRATION_FAILED);

    const std::uint64_t did = msr.get_did();
    if (did == 0) return std::unexpected(Error::DIVISION_BY_ZERO);

    return ((msr.get_fid() * 200ul) / did) * 1'000'000ul;
  }

  if (uarch == Microarchitecture::AMD_PHENOM ||
      uarch == Microarchitecture::AMD_BULLDOZER) {
    auto msr = read<AmdLegacyPstateMsr>();

    if (!msr.is_valid())
      return std::unexpected(Error::DIRECT_CALIBRATION_FAILED);

    const std::uint64_t ratio   = (msr.get_fid() + 0x10);
    const std::uint64_t divisor = (1ul << msr.get_did());

    return ((100ul * ratio) / divisor) * 1'000'000ul;
  }

  return std::unexpected(Error::UNSUPPORTED_ARCHITECTURE);
}

std::expected<void, Error> Clock::initialize() noexcept {
  if (s_frequency_hz != 0) [[unlikely]]
    return std::unexpected(Error::ALREADY_INITIALIZED);

  ProcessorState& state             = get_current_state();
  const HypervisorState& hypervisor = state.hypervisor();
  const ProcessorIdentity& identity = state.identity();
  const Microarchitecture uarch     = identity.microarch;

  s_has_rdtscp = state.has_feature(CpuFeature::RDTSCP);

  if (!state.has_feature(CpuFeature::TSC_INVARIANT))
    return std::unexpected(Error::NO_INVARIANT_TSC);

  std::expected<std::uint64_t, Error> res =
      std::unexpected(Error::UNSUPPORTED_ARCHITECTURE);

  if (hypervisor.is_virtualized) {
    res = calibrate_vm(hypervisor);
  } else {
    if (uarch >= Microarchitecture::INTEL_NEHALEM &&
        uarch <= Microarchitecture::INTEL_ARROW_LAKE) {
      res = calibrate_intel(state.max_leaf(), uarch);
    } else if (
        uarch >= Microarchitecture::AMD_PHENOM &&
        uarch <= Microarchitecture::AMD_ZEN5
    ) {
      res = calibrate_amd(uarch);
    }
  }

  if (res.has_value()) [[likely]]
    s_frequency_hz = res.value();
  else
    s_frequency_hz = boot::tsc_request.response->frequency;

  // scale down by 10^7, adding 5*10^6 to round to the nearest 100th
  const std::uint64_t scaled_hz = (s_frequency_hz + 5'000'000ul) / 10'000'000ul;
  tsc_logger.info(
      "Initialized TSC (frequency = %lu.%luGHz)",
      scaled_hz / 100ul,
      scaled_hz % 100ul
  );

  return {};
}

std::uint64_t Clock::now(hal::smp::CpuId* cpu_id) noexcept {
  std::uint32_t lo, hi;
  hal::smp::CpuId aux;

  if (s_has_rdtscp) [[likely]] {
    asm volatile("rdtscp" : "=a"(lo), "=d"(hi), "=c"(aux)::"memory");

    if (cpu_id) *cpu_id = aux;
  } else [[unlikely]] {
    asm volatile("lfence" ::: "memory");
    asm volatile("rdtsc" : "=a"(lo), "=d"(hi)::"memory");
    asm volatile("lfence" ::: "memory");

    // Must fetch Core ID via LAPIC
    if (cpu_id) *cpu_id = static_cast<hal::smp::CpuId>(UINT32_MAX);
  }

  return (static_cast<std::uint64_t>(hi) << 32) | lo;
}
}  // namespace kernel::x86_64::cpu::tsc