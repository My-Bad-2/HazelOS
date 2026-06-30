#ifndef KERNEL_INCLUDE_ARCH_CPU_IDT_HPP
#define KERNEL_INCLUDE_ARCH_CPU_IDT_HPP 1

#include <expected>

#include "cpu/interrupts/common.hpp"
#include "cpu/interrupts/dispatch.hpp"
#include "cpu/interrupts/fred.hpp"
#include "cpu/interrupts/idt.hpp"

namespace kernel {
namespace x86_64 {
namespace cpu {
namespace interrupts {
struct EventConfig {
  void* fred_entry_page;
  fred::FRED_STKLVLS fred_stack_levels;
  const idt::Table<256>& idt;
};

class DeliveryManager {
 public:
  __nodiscard static std::expected<ActiveMode, InterruptErrors> initialize(
      const EventConfig& config
  ) noexcept;
};
}  // namespace interrupts
}  // namespace cpu
}  // namespace x86_64
}  // namespace kernel

#endif