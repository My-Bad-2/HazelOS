#ifndef KERNEL_ARCH_UART_HPP
#define KERNEL_ARCH_UART_HPP 1

#include <cstdint>

#include "compiler.h"
#include "core/log_sink.hpp"
#include "hal/cpu.hpp"

namespace kernel {
namespace x86_64 {
namespace uart {
enum class RegisterOffset : std::uint8_t {
  Data = 0,                 // RBR (read) / THR (write)
  InterruptEnable,          // IER
  InterruptIdentification,  // IIR (read) / FCR (write)
  LineControl,              // LCR
  ModemControl,             // MCR
  LineStatus,               // LSR
  ModemStatus,              // MSR
  Scratch,                  // SCR

  // Divisor Latch Registers (accessible only when LCR DLAB bit is set)
  BaudRateLow    = 0,  // DLL
  BaudRateHigh   = 1,  // DLH
  FifoController = 2,  // FCR (Write only)
};
}  // namespace uart

class UartSink final : public core::LogSink {
 public:
  explicit UartSink(std::uint16_t base_port = 0x3f8) noexcept
      : m_base_port(base_port) {}

  void initialize() noexcept;

 private:
  std::uint16_t m_base_port;

  __nodiscard std::uint8_t read_register(
      uart::RegisterOffset offset
  ) const noexcept;

  void write_register(uart::RegisterOffset offset, uint8_t value) noexcept;

  template <std::uint8_t Flag>
  void wait_for_status() const noexcept {
    while ((read_register(uart::RegisterOffset::LineStatus) & Flag) == 0)
      hal::cpu::pause();
  }

  void transmit(char ch) noexcept override;
  void flush_fifo() noexcept override;
};
}  // namespace x86_64
}  // namespace kernel

#endif  // KERNEL_ARCH_UART_HPP