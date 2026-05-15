#ifndef KERNEL_HAL_CPU_HPP
#define KERNEL_HAL_CPU_HPP 1

#include <cstddef>
#include <cstdint>

#include "compiler.h"

namespace kernel {
namespace hal {
namespace cpu {
/**
 * Toggle hardware interrupts.
 *
 * Set @param interrupts to true to enable interrupts, otherwise false to
 * disable.
 */
void toggle_interrupts(bool interrupts);

/**
 * Sets the stack pointer to `stack + size` address and calls to func()
 */
void set_stack_pointer(void* stack, std::size_t size, void (*func)());

void disable_interrupts() noexcept;
void enable_interrupts() noexcept;
std::uint64_t save_interrupt_state() noexcept;
void restore_interrupt_state(std::uint64_t state) noexcept;
bool are_interrupts_enabled() noexcept;

void pause() noexcept;
__noreturn void halt(bool interrupts) noexcept;
}  // namespace cpu
}  // namespace hal
}  // namespace kernel

#endif