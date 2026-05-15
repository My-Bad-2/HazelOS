#include "hal/cpu.hpp"

#include <cstdint>

namespace kernel {
namespace hal {
namespace cpu {
void set_stack_pointer(void* stack, std::size_t size, void (*func)()) {
  auto stack_top = reinterpret_cast<std::uintptr_t>(stack) + size;
  stack_top &= ~0xful;
  asm volatile(
      "mov %%rsp, %%r12\n\t"  // Save current stack pointer to a callee-saved
                              // register (r12)
      "mov %0, %%rsp\n\t"     // Set rsp to new stack_top
      "call *%1\n\t"          // Call the target function
      "mov %%r12, %%rsp\n\t"  // Restore the original stack pointer
      ::"r"(stack_top),
      "r"(func)
      : "r12",
        "memory",
        "cc",
        "rax",
        "rcx",
        "rdx",
        "rsi",
        "rdi",
        "r8",
        "r9",
        "r10",
        "r11"
  );
}

void disable_interrupts() noexcept {
  asm volatile("cli" ::: "memory");
}

void enable_interrupts() noexcept {
  asm volatile("sti" ::: "memory");
}

std::uint64_t save_interrupt_state() noexcept {
  std::uint64_t rflags;
  asm volatile("pushfq\n\tpop %0" : "=r"(rflags)::"memory");
  return rflags;
}

void restore_interrupt_state(std::uint64_t state) noexcept {
  asm volatile("push %0\n\tpopfq" ::"r"(state) : "memory", "cc");
}

bool are_interrupts_enabled() noexcept {
  return (save_interrupt_state() & (1ul << 9)) != 0;
}
}  // namespace cpu
}  // namespace hal
}  // namespace kernel