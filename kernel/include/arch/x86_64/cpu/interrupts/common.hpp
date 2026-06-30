#ifndef KERNEL_INCLUDE_ARCH_CPU_INTERRUPTS_COMMON_HPP
#define KERNEL_INCLUDE_ARCH_CPU_INTERRUPTS_COMMON_HPP 1

#include <cstdint>

namespace kernel::x86_64::cpu::interrupts {
enum class ActiveMode : std::uint8_t { IDT, FRED };
enum class PrivilegeLevel : std::uint8_t { RING0 = 0, RING1, RING2, RING3 };

enum InterruptVectors : std::uint8_t {
  DIVIDE_ERROR = 0,             // DIV / IDIV
  DEBUG_EXCEPTION,              // Breakpoints
  NMI,                          // NMI External Interrupts
  BREAKPOINT,                   // INT3
  OVERFLOW,                     // INTO
  BOUND_RANGE_EXCEEDED,         // BOUND
  INVALID_OPCODE,               // Undefined or reserved opcode
  DEVICE_NOT_AVAILABLE,         // FP or WAIT/FWAIT instructions
  DOUBLE_FAULT,                 // INTR/NMI/Instruction that generate exception
  COPROCESSOR_SEGMENT_OVERRUN,  // FPU Instruction (Intel only)
  INVALID_TSS,                  // Task Switch or TSS access
  SEGMENT_NOT_PRESENT,          // Loading / accessing segment registers
  STACK_SEGMENT_FAULT,          // Stack operations and SS register loads
  GENERAL_PROTECTION,  // Any memory reference and other protection checks
  PAGE_FAULT,          // Any Memory reference
  MATH_FAULT = 16,     // x87-FPU FP or WAIT/FWAIT instructions
  ALIGNMENT_CHECK,     // Data reference in memory
  MACHINE_CHECK,       // note: model-dependent causes
  SIMD_FP,             // SSE/SSE2/SSE3 FP instructions
  VIRTUALIZATION,      // EPT violations (Intel only)
  CONTROL_PROTECTION,  // RET/IRET/RSTORSSP/SETSSBSY/ missing ENDBRANCH (CET)
  HYPERVISOR_INJECTION = 28,  // Event Injection (AMD only)
  VMM_COMM,                   // Virtualization Event (AMD only)
  SECURITY_EXCEPTION,         // Security-sensitive event under SVM (AMD only)
  USER_BASE         = 0x20,
  APIC_SPURIOUS_INT = 0xff,
  USER_MAX          = 0xff
};

enum class InterruptErrors : std::uint8_t {
  FRED_UNSUPPORTED,
  FRED_MISALIGNED_ENTRYPOINT,
  IDT_LOAD_FAILED
};

enum class EventType : std::uint8_t {
  EXT_INTERRUPT           = 0,  // INTR
  NMI                     = 1,  // NMI
  HARDWARE_EXCEPTION      = 3,  // PF
  SW_INTERRUPT            = 4,  // INT n
  PRIVILEGED_SW_EXCEPTION = 5,  // INT1
  SW_EXCEPTION            = 6,  // INT3/INTO
  OTHER                   = 7,  // SYSCALL/SYSENTER, etc.
};
}  // namespace kernel::x86_64::cpu::interrupts

#endif