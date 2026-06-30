#ifndef KERNEL_INCLUDE_ARCH_CPU_INTERRUPTS_DISPATCH_HPP
#define KERNEL_INCLUDE_ARCH_CPU_INTERRUPTS_DISPATCH_HPP 1

#include <cstdint>

namespace kernel::x86_64::cpu {
struct CpuContext {
  std::uint64_t rax;  // Offset 0
  std::uint64_t rbx;  // Offset 8
  std::uint64_t rcx;  // Offset 16
  std::uint64_t rdx;  // Offset 24
  std::uint64_t rsi;  // Offset 32
  std::uint64_t rdi;  // Offset 40
  std::uint64_t rbp;  // Offset 48
  std::uint64_t r8;   // Offset 56
  std::uint64_t r9;   // Offset 64
  std::uint64_t r10;  // Offset 72
  std::uint64_t r11;  // Offset 80
  std::uint64_t r12;  // Offset 88
  std::uint64_t r13;  // Offset 96
  std::uint64_t r14;  // Offset 104
  std::uint64_t r15;  // Offset 112
};

struct IdtFrame {
  CpuContext gprs;
  std::uint64_t vector;
  std::uint64_t error_code;
  std::uint64_t rip;
  std::uint64_t cs;
  std::uint64_t rflags;
  std::uint64_t rsp;
  std::uint64_t ss;
};

union FredEventData {
  std::uint64_t raw;
  struct {
    std::uint64_t vector    : 8;
    std::uint64_t reserved  : 8;
    std::uint64_t type      : 4;  // 0 = Ext. Interrupt, 2 = NMI, 3 = Exception
    std::uint64_t reserved2 : 44;
  } bits;
};

struct FredFrame {
  CpuContext gprs;
  std::uint64_t error_code;
  FredEventData event_data;
  std::uint64_t rip;
  std::uint64_t cs;
  std::uint64_t rflags;
  std::uint64_t rsp;
  std::uint64_t ss;
};

namespace interrupts {
extern "C" void idt_dispatch(IdtFrame* frame);
extern "C" void fred_dispatch(FredFrame* frame);
}  // namespace interrupts
}  // namespace kernel::x86_64::cpu

#endif