#ifndef KERNEL_ARCH_CORE_UART_HPP
#define KERNEL_ARCH_CORE_UART_HPP 1

#include <cstdint>

#include "compiler.h"
#include "core/log_sink.hpp"
#include "hal/cpu.hpp"

namespace kernel {
namespace aarch64 {
namespace pl011 {
enum class Register : std::uint8_t {
  Data           = 0x000,  // UARTDR: Data Register
  ReceiveStatus  = 0x004,  // UARTRSR/UARTECR: Receive Status / Error Clear
  Flag           = 0x018,  // UARTFR: Flag Register
  IntegerBaud    = 0x024,  // UARTIBRD: Integer Baud Rate Divisor
  FractionBaud   = 0x028,  // UARTFBRD: Fractional Baud Rate Divisor
  LineControl    = 0x02c,  // UARTLCR_H: Line Control Register
  Control        = 0x030,  // UARTCR: Control Register
  InterruptMask  = 0x038,  // UARTIMSC: Interrupt Mask Set/Clear
  InterruptClear = 0x044,  // UARTICR: Interrupt Clear Register
  DMACR          = 0x048   // UARTDMACR
};
}

class UartSink final : public core::LogSink {
 public:
  explicit UartSink(std::uintptr_t base_address) noexcept
      : m_mmio_base(base_address) {}

  void initialize(std::uint64_t base_clock, std::uint32_t target_baud) noexcept;

 private:
  std::uintptr_t m_mmio_base;

  template <std::uint32_t Flag>
  void wait_for_status() const noexcept {
    while ((read_register(pl011::Register::Flag) & Flag) == 0)
      hal::cpu::pause();
  }

  __nodiscard std::uint32_t read_register(pl011::Register reg) const
      volatile noexcept;
  void write_register(pl011::Register reg, std::uint32_t val) volatile noexcept;

  void transmit(char ch) noexcept override;
  void flush_fifo() noexcept override;
};
}  // namespace aarch64
}  // namespace kernel

#endif  // KERNEL_ARCH_CORE_UART_HPP