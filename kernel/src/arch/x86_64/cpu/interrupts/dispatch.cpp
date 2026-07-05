#include "cpu/interrupts/dispatch.hpp"

#include <atomic>
#include <concepts>
#include <cstdint>

#include "compiler.h"
#include "core/logger.hpp"
#include "cpu/interrupts/common.hpp"
#include "cpu/smp.hpp"

namespace kernel::x86_64::cpu::interrupts {
namespace {
log::Logger interrupt_logger{"INTERRUPT"};

template <typename T>
concept HardwareFrame = std::same_as<T, IdtFrame> || std::same_as<T, FredFrame>;

using namespace hal::smp;

class Dispatcher {
 private:
  __always_inline static void ack_hardware(
      hal::smp::PerCpuState& cpu
  ) noexcept {
    cpu.lapic.send_eoi();
  }

  template <HardwareFrame Frame>
  static void dump_registers(const Frame* frame) noexcept {
    interrupt_logger.error(
        "\r\n"
        "========================== CPU EXCEPTION STATE "
        "=================================\r\n"
        " RAX: %016llx    RBX: %016llx    RCX: %016llx\r\n"
        " RDX: %016llx    RSI: %016llx    RDI: %016llx\r\n"
        " RBP: %016llx    R08: %016llx    R09: %016llx\r\n"
        " R10: %016llx    R11: %016llx    R12: %016llx\r\n"
        " R13: %016llx    R14: %016llx    R15: %016llx\r\n"
        "----------------------------------------------------------------------"
        "----------\r\n"
        " RIP: %016llx    RSP: %016llx    RFL: %016llx\r\n"
        " CS:  %04llx                SS:  %04llx                ERR: "
        "%016llx\r\n"
        "======================================================================"
        "==========",
        frame->gprs.rax,
        frame->gprs.rbx,
        frame->gprs.rcx,
        frame->gprs.rdx,
        frame->gprs.rsi,
        frame->gprs.rdi,
        frame->gprs.rbp,
        frame->gprs.r8,
        frame->gprs.r9,
        frame->gprs.r10,
        frame->gprs.r11,
        frame->gprs.r12,
        frame->gprs.r13,
        frame->gprs.r14,
        frame->gprs.r15,
        frame->rip,
        frame->rsp,
        frame->rflags,
        frame->cs,
        frame->ss,
        frame->error_code
    );
  }

  template <HardwareFrame Frame>
  __hot __always_inline static void handle_external(
      PerCpuState& cpu,
      Frame* frame,
      std::uint64_t vector,
      bool from_user
  ) noexcept {
    cpu.enter_hard_irq();
    std::atomic_signal_fence(std::memory_order_seq_cst);

    // Fetch the bounded irq thread from the per-cpu-state

    // Manage ipis
    ack_hardware(cpu);
    if (vector == URGENT_IPI) cpu.process_ipis();

    std::atomic_signal_fence(std::memory_order_seq_cst);
    cpu.exit_hard_irq();

    // If the CPU needs to rescheduled, reschedule here
    if (from_user && cpu.preempt_count().is_preemptible()) {
      // reset the need for rescheduling
      // tail call the scheduler
    }
  }

  template <HardwareFrame Frame>
  __hot __always_inline static void
  handle_syscall(PerCpuState& cpu, Frame* frame, bool from_user) noexcept {
    if (!from_user) [[unlikely]]
      interrupt_logger.fatal("SYSCALL executed from Ring 0");

    // Dispatch syscall
  }

  template <HardwareFrame Frame>
  __cold __noinline static void handle_other_events(
      PerCpuState& cpu,
      Frame* frame,
      EventType type,
      std::uint64_t vector,
      std::uint64_t err,
      bool from_user
  ) noexcept {
    switch (type) {
      case EventType::HARDWARE_EXCEPTION: {
        cpu.enter_hard_irq();

        if (vector == InterruptVectors::PAGE_FAULT && from_user) [[likely]] {
          // Wakeup the pager thread
        } else {
          dump_registers(frame);
          interrupt_logger.fatal("Fatal Hardware Exception");
        }

        cpu.exit_hard_irq();
        break;
      }
      case EventType::SW_EXCEPTION:
      case EventType::PRIVILEGED_SW_EXCEPTION: {
        // INT3 (breakpoint), INTO (Overflow), or INT1 (ICEBP)
        // Route to the debugger
        break;
      }
      case EventType::SW_INTERRUPT: {
        interrupt_logger.fatal("Unexpected Software Interrupt");
        break;
      }
      case EventType::NMI: {
        cpu.enter_nmi();
        std::atomic_signal_fence(std::memory_order_seq_cst);
        // Process NMI
        cpu.process_nmis();
        std::atomic_signal_fence(std::memory_order_seq_cst);
        cpu.exit_nmi();
        break;
      }
      case EventType::EXT_INTERRUPT:
      case EventType::OTHER:
      default:
        interrupt_logger.fatal(
            "Unknown Event Type mapped in hardware (type: %u)",
            type
        );
        break;
    }

    if (from_user && cpu.preempt_count().is_preemptible()) {
      // needs rescheduling, schedule a tail call
    }
  }

 public:
  template <HardwareFrame Frame>
  __always_inline static void dispatch(
      Frame* frame,
      EventType type,
      std::uint8_t vector,
      std::uint64_t err_code
  ) noexcept {
    if (vector == InterruptVectors::APIC_SPURIOUS_INT)
      return;  // Don't process Spurious interrupt

    hal::smp::PerCpuState& cpu = hal::smp::get_cpu_state();
    const bool from_user       = (frame->cs & 3) == 3;

    if (type == EventType::EXT_INTERRUPT) [[likely]]
      handle_external(cpu, frame, vector, from_user);
    else if (type == EventType::OTHER && vector == 1) [[likely]]
      handle_syscall(cpu, frame, from_user);
    else [[unlikely]]
      handle_other_events(cpu, frame, type, vector, err_code, from_user);
  }
};

__nodiscard constexpr EventType vector_to_event_type(
    std::uint8_t vector
) noexcept {
  if (vector == InterruptVectors::NMI) return EventType::NMI;

  if (vector < 32) {
    switch (vector) {
      case InterruptVectors::BREAKPOINT:
      case InterruptVectors::OVERFLOW:
      case InterruptVectors::BOUND_RANGE_EXCEEDED:
        return EventType::SW_EXCEPTION;
      case InterruptVectors::DEBUG_EXCEPTION:
        // Check DR6 here:
        if (false) return EventType::PRIVILEGED_SW_EXCEPTION;
        return EventType::HARDWARE_EXCEPTION;
      default:
        return EventType::HARDWARE_EXCEPTION;
    }
  }

  return EventType::EXT_INTERRUPT;
}
}  // namespace

void idt_dispatch(IdtFrame* frame) {
  const std::uint8_t vector      = frame->vector;
  const std::uint64_t error_code = frame->error_code;
  const EventType event_type     = vector_to_event_type(vector);

  Dispatcher::dispatch(frame, event_type, vector, error_code);
}

void fred_dispatch(FredFrame* frame) {
  const EventType type = static_cast<EventType>(frame->event_data.bits.type);
  const std::uint8_t vector      = frame->event_data.bits.vector;
  const std::uint64_t error_code = frame->error_code;

  Dispatcher::dispatch(frame, type, vector, error_code);
}
}  // namespace kernel::x86_64::cpu::interrupts
