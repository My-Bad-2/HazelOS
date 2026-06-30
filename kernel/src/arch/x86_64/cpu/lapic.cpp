#include "cpu/lapic.hpp"

#include <cstdint>
#include <expected>

#include "compiler.h"
#include "cpu/interrupts/common.hpp"
#include "cpu/lapic/regs.hpp"
#include "cpu/registers.hpp"
#include "hal/cpu.hpp"
#include "memory/address/physical.hpp"
#include "memory/vmm.hpp"

namespace kernel {
namespace x86_64 {
namespace cpu {
namespace lapic {
namespace {
constexpr std::uint64_t LAPIC_BASE_VIRT = 0xffffffffffffe000ul;
}  // namespace

std::expected<void, ApicError>
LocalApic::initialize(std::uint8_t spurious_vec, bool enable_x2apic) noexcept {
  if (spurious_vec < interrupts::InterruptVectors::USER_BASE)
    __unlikely return std::unexpected(ApicError::InvalidVector);

  auto base = x86_64::cpu::read<ApicBaseMsr>();
  base.enable_global();
  if (m_is_x2apic) base.enable_x2apic();
  x86_64::cpu::write(base);

  if (!enable_x2apic)
    static auto once = [&]() {
      std::uintptr_t lapic_base = base.get_base();
      memory::VirtualManager::map_mmio(
          memory::VirtAddr(LAPIC_BASE_VIRT),
          memory::PhysAddr(lapic_base)
      );

      return true;
    }();

  m_is_x2apic  = enable_x2apic;
  m_xapic_base = LAPIC_BASE_VIRT;

  constexpr std::uint32_t SUPPORTS_EOI_BROADCAST_SUPPRESSION = (1 << 24);

  auto ver_reg      = read<VER>();
  m_max_lvt_entries = ((ver_reg.raw32 >> 16) & 0xff) + 1;

  const bool supports_directed_eoi =
      ver_reg.raw32 & SUPPORTS_EOI_BROADCAST_SUPPRESSION;

  constexpr std::uint32_t SIVR_APIC_SW_ENABLE         = (1 << 8);
  constexpr std::uint32_t SIVR_SUPPRESS_EOI_BROADCAST = (1 << 12);

  write(
      SIVR{
          SIVR_APIC_SW_ENABLE | spurious_vec |
          (supports_directed_eoi && SIVR_SUPPRESS_EOI_BROADCAST)
      }
  );
  set_task_priority(0);

  return {};
}

// ticks = (bus_frequency / divider) * desired_seconds
std::expected<void, ApicError> LocalApic::arm_periodic(
    std::uint8_t vector,
    std::uint32_t ticks,
    TimerDivide div
) noexcept {
  if (vector < interrupts::InterruptVectors::USER_BASE)
    __unlikely return std::unexpected(ApicError::InvalidVector);

  std::uint32_t lvt = LvtConfig{}
                          .vector(vector)
                          .timer_mode(TimerMode::PERIODIC)
                          .mask(false)
                          .raw();

  write(TMR_DCR{static_cast<std::uint32_t>(div)});
  write(LVT_TMR{lvt});
  write(TMR_ICR{ticks});

  return {};
}

std::expected<void, ApicError> LocalApic::arm_tsc_deadline(
    std::uint8_t vector,
    std::uint64_t absolute_tsc
) noexcept {
  if (vector < interrupts::InterruptVectors::USER_BASE)
    __unlikely return std::unexpected(ApicError::InvalidVector);

  std::uint32_t lvt = LvtConfig{}
                          .vector(vector)
                          .timer_mode(TimerMode::TSC_DEADLINE)
                          .mask(false)
                          .raw();

  write(LVT_TMR{lvt});

  // TSC-Deadline bypasses the ICR
  x86_64::cpu::write(TscDeadlineMsr{.raw = absolute_tsc});
  return {};
}

std::expected<void, ApicError> LocalApic::send_ipi(
    const IcrConfig& config,
    bool is_nmi_context
) const noexcept {
  if (m_is_x2apic) __likely {
      // x2APIC Mode: IPIs are dispatched via a single 64-bit MSR write.
      x86_64::cpu::write(X2ApicIcr{.raw = config.to_x2apic()});
      return {};
    }

  // xAPIC Fallback: IPIs require two separate 32-bit MMIO writes. The caller
  // must ensure local interrupts are disabled before executing this block
  // to prevent ISR preemption.
  constexpr std::uint32_t DELIVERY_STATUS_BIT = (1 << 12);

  if (is_nmi_context) {
    if (!m_xapic_icr_lock.try_lock())
      if (config.get_delivery() != IpiDelivery::NMI)
        return std::unexpected(ApicError::IpiPreempted);
  } else
    m_xapic_icr_lock.lock();

  // Wait for the delivery Status bit to clear from any prior IPI.
  std::uint32_t timeout = 1'000'000;
  while (read<ICR_LOW>().raw32 & DELIVERY_STATUS_BIT) {
    if (--timeout == 0) __unlikely {
        if (!is_nmi_context) m_xapic_icr_lock.unlock();
        return std::unexpected(ApicError::IpiDeliveryTimeout);
      }

    hal::cpu::pause();
  }

  // Write the Destination ID
  write(ICR_HIGH{config.high() << 24});

  // Write the Command
  write(ICR_LOW{config.low()});

  if (!is_nmi_context) m_xapic_icr_lock.unlock();
  return {};
}

void LocalApic::suspend() noexcept {
  m_suspend_tmr   = read<LVT_TMR>().raw32;
  m_suspend_pmc   = read<LVT_PMC>().raw32;
  m_suspend_lint0 = read<LVT_LINT0>().raw32;
  m_suspend_lint1 = read<LVT_LINT1>().raw32;
  m_suspend_err   = read<LVT_ERR>().raw32;
  m_suspend_sivr  = read<SIVR>().raw32;

  if (m_max_lvt_entries >= 6) m_suspend_cmci = read<LVT_CMCI>().raw32;
}

void LocalApic::resume() noexcept {
  auto base = x86_64::cpu::read<ApicBaseMsr>();
  base.enable_global();
  if (m_is_x2apic) base.enable_x2apic();
  x86_64::cpu::write(base);

  write(SIVR{m_suspend_sivr});
  write(LVT_TMR{m_suspend_tmr});
  write(LVT_PMC{m_suspend_pmc});
  write(LVT_LINT0{m_suspend_lint0});
  write(LVT_LINT1{m_suspend_lint1});
  write(LVT_ERR{m_suspend_err});

  if (m_max_lvt_entries >= 6) write(LVT_CMCI{m_suspend_cmci});
}

void LocalApic::setup_nmi(bool on_lint1) noexcept {
  std::uint32_t lvt = LvtConfig{}.delivery(LvtDelivery::NMI).mask(false).raw();

  if (on_lint1)
    write(LVT_LINT1{lvt});
  else
    write(LVT_LINT0{lvt});
}

std::expected<void, ApicError> LocalApic::setup_profiler(
    std::uint8_t vector
) noexcept {
  if (vector < interrupts::InterruptVectors::USER_BASE)
    __unlikely return std::unexpected(ApicError::InvalidVector);

  std::uint32_t lvt = LvtConfig{}.vector(vector).mask(false).raw();
  write(LVT_PMC{lvt});

  return {};
}

std::expected<void, ApicError> LocalApic::setup_cmci(
    std::uint8_t vector
) noexcept {
  if (m_max_lvt_entries < 6) return std::unexpected(ApicError::HardwareFault);
  if (vector < interrupts::InterruptVectors::USER_BASE)
    __unlikely return std::unexpected(ApicError::InvalidVector);

  std::uint32_t lvt = LvtConfig{}.vector(vector).mask(false).raw();
  write(LVT_CMCI{lvt});
  return {};
}

std::expected<void, ApicError>
LocalApic::broadcast_ipi(std::uint8_t vector, bool include_self) noexcept {
  if (vector < interrupts::InterruptVectors::USER_BASE)
    __unlikely return std::unexpected(ApicError::InvalidVector);

  auto broadcast = IcrConfig{}
                       .vector(vector)
                       .delivery(IpiDelivery::FIXED)
                       .shorthand(
                           include_self ? IpiShorthand::ALL_INCLUDING_SELF
                                        : IpiShorthand::ALL_EXCLUDING_SELF
                       );

  return send_ipi(broadcast);
}

void LocalApic::send_eoi() const noexcept {
  write(EOI{0});
}

std::expected<void, ApicError> LocalApic::broadcast_multicast_ipi(
    std::uint16_t cluster_id,
    std::uint16_t core_mask,
    std::uint8_t vector
) const noexcept {
  auto icr = IcrConfig{}
                 .vector(vector)
                 .delivery(IpiDelivery::FIXED)
                 .dest_mode(IpiDestMode::LOGICAL)
                 .cluster_destination(cluster_id, core_mask);

  return send_ipi(icr);
}

HardwareErrorStatus LocalApic::read_hardware_errors() const noexcept {
  // Write 0 before reading to update the internal state
  write(ESR{0});
  auto esr = read<ESR>();
  return HardwareErrorStatus{esr.raw32};
}

void LocalApic::send_self_ipi(std::uint8_t vector) const noexcept {
  if (m_is_x2apic)
    __likely return x86_64::cpu::write(X2ApicSelfIpi{.raw = vector});

  // xAPIC fallback: Rely on `send_ipi` to handle ICR spinlock
  auto self_cmd = IcrConfig{}
                      .vector(vector)
                      .delivery(IpiDelivery::FIXED)
                      .shorthand(IpiShorthand::SELF);

  __maybe_unused auto _ = send_ipi(self_cmd);
}
}  // namespace lapic
}  // namespace cpu
}  // namespace x86_64
}  // namespace kernel