#ifndef KERNEL_HAL_HPP
#define KERNEL_HAL_HPP 1

namespace kernel {
namespace hal {
void early_init() noexcept;
void initialize() noexcept;
}  // namespace hal
}  // namespace kernel

#endif  // KERNEL_HAL_HPP