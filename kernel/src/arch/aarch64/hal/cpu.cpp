#include "hal/cpu.hpp"

#include <cstdint>

namespace kernel {
namespace hal {
namespace cpu {
void set_stack_pointer(void* stack, std::size_t size, void (*func)()) {
  auto stack_top = reinterpret_cast<std::uintptr_t>(stack) + size;
  stack_top &= ~0xfu;

  asm volatile(
      "mov x19, sp\n\t"  // Save current SP to callee-saved register x19
      "mov sp, %0\n\t"   // Set SP to stack_top
      "blr %1\n\t"       // Branch with Link to target function
      "mov sp, x19\n\t"  // Restore original SP
      :
      : "r"(stack_top), "r"(func)
      // clang-format off
      : "x19", "x30", "memory", "cc",
        // Caller-saved General Purpose Registers
        "x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7",
        "x8", "x9", "x10", "x11","x12", "x13", "x14",
        "x15", "x16", "x17", "x18",
        // Caller-saved Floating Point / SIMD Registers
        "v0", "v1", "v2", "v3", "v4", "v5", "v6", "v7",
        "v16", "v17", "v18", "v19", "v20", "v21", "v22", "v23",
        "v24", "v25", "v26", "v27", "v28", "v29", "v30", "v31"
      // clang-format on
  );
}

void disable_interrupts() noexcept {
  // DAIF bits: Debug, SError, IRQ, FIQ
  asm volatile("msr daifset, #3" ::: "memory");
}

void enable_interrupts() noexcept {
  asm volatile("msr daifclr, #3" ::: "memory");
}

std::uint64_t save_interrupt_state() noexcept {
  std::uint64_t daif;
  asm volatile("mrs %0, daif" : "=r"(daif)::"memory");
  return daif;
}

void restore_interrupt_state(std::uint64_t state) noexcept {
  asm volatile("msr daif, %0" ::"r"(state) : "memory");
}

bool are_interrupts_enabled() noexcept {
  return (save_interrupt_state() & (1ul << 7)) == 0;
}
}  // namespace cpu
}  // namespace hal
}  // namespace kernel