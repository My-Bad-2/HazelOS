#ifndef KERNEL_ARCH_X86_64_CPU_SMP_HPP
#define KERNEL_ARCH_X86_64_CPU_SMP_HPP 1

#include <new>

#include "cpu/feats.hpp"
#include "cpu/registers.hpp"
#include "hal/smp.hpp"

namespace kernel {
namespace hal {
namespace smp {
class alignas(std::hardware_constructive_interference_size) PerCpuState final {
 private:
  PerCpuState* const m_self;
  CoreState m_core;

  const ApicId m_apic_id;
  x86_64::cpu::ProcessorState m_state;

 public:
  constexpr PerCpuState(CpuId id, NumaId numa, ApicId apic) noexcept
      : m_self(this), m_core(id, numa), m_apic_id(apic) {}

  __nodiscard CoreState& core_state() noexcept {
    return m_core;
  }

  __nodiscard constexpr x86_64::cpu::ProcessorState&
  processor_state() noexcept {
    return m_state;
  }

  __nodiscard constexpr ApicId apic_id() const noexcept {
    return m_apic_id;
  }

  __nodiscard constexpr const PerCpuState* self() const noexcept {
    return m_self;
  }
};

void initialize_cpu_hw(PerCpuState* cpu) noexcept;
}  // namespace smp
}  // namespace hal
}  // namespace kernel

#endif