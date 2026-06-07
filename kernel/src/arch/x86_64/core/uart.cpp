#include "core/uart.hpp"

#include <cstdint>

#include "cpu.hpp"
#include "guards.hpp"

namespace kernel {
namespace x86_64 {
namespace {
// Line Control Register (LCR) Bits
struct LineControl {
  static constexpr uint8_t DataSize5 = 0x00;
  static constexpr uint8_t DataSize6 = 0x01;
  static constexpr uint8_t DataSize7 = 0x02;
  static constexpr uint8_t DataSize8 = 0x03;

  // Divisor Latch Access Bit
  static constexpr uint8_t DlabEnable = (1 << 7);
};

// Modem Control Register (MCR) Bits
struct ModemControl {
  static constexpr uint8_t DataTerminalReady = (1 << 0);  // DTR
  static constexpr uint8_t RequestToSend     = (1 << 1);  // RTS
  static constexpr uint8_t Out1              = (1 << 2);
  static constexpr uint8_t Out2              = (1 << 3);
  static constexpr uint8_t LoopbackMode      = (1 << 4);
};

// Interrupt Enable Register (IER) Bits
struct InterruptEnable {
  static constexpr uint8_t DataAvailable     = (1 << 0);  // RX data available
  static constexpr uint8_t TransmitterEmpty  = (1 << 1);  // TX empty
  static constexpr uint8_t LineStatusChange  = (1 << 2);  // RX status changed
  static constexpr uint8_t ModemStatusChange = (1 << 3);  // Modem status change
};

// Line Status Register (LSR) Bits
struct LineStatus {
  static constexpr uint8_t DataReady           = (1 << 0);
  static constexpr uint8_t OverrunError        = (1 << 1);
  static constexpr uint8_t ParityError         = (1 << 2);
  static constexpr uint8_t FramingError        = (1 << 3);
  static constexpr uint8_t BreakIndicator      = (1 << 4);
  static constexpr uint8_t TransmitBufferEmpty = (1 << 5);  // THRE
  static constexpr uint8_t TransmitterIdle     = (1 << 6);  // TEMT
  static constexpr uint8_t ImpendingError      = (1 << 7);  // Error in RX FIFO
};

// FIFO Control Register (FCR) Bits
struct FifoControl {
  static constexpr uint8_t Enable        = (1 << 0);
  static constexpr uint8_t ClearReceive  = (1 << 1);
  static constexpr uint8_t ClearTransmit = (1 << 2);
  static constexpr uint8_t Enable64Byte  = (1 << 5);  // 16750 only

  // Interrupt Trigger Levels
  static constexpr uint8_t TriggerLevel1 = (0 << 6);  // 1 byte
  static constexpr uint8_t TriggerLevel2 = (1 << 6);  // 4 bytes
  static constexpr uint8_t TriggerLevel3 = (2 << 6);  // 8 bytes
  static constexpr uint8_t TriggerLevel4 = (3 << 6);  // 14 bytes
};
}  // namespace

void UartSink::write_register(
    uart::RegisterOffset offset,
    std::uint8_t val
) noexcept {
  cpu::port_write(
      std::uint16_t(m_base_port + static_cast<std::uint16_t>(offset)),
      val
  );
}

std::uint8_t UartSink::read_register(
    uart::RegisterOffset offset
) const noexcept {
  return cpu::port_read<std::uint8_t>(
      std::uint16_t(m_base_port + static_cast<std::uint16_t>(offset))
  );
}

void UartSink::flush() noexcept {
  wait_for_status<LineStatus::TransmitterIdle>();
}

void UartSink::write(std::string_view str) noexcept {
  const common::LockGuard _(m_lock);
  for (const auto ch : str) {
    wait_for_status<LineStatus::TransmitBufferEmpty>();
    write_register(uart::RegisterOffset::Data, static_cast<uint8_t>(ch));
  }
}

void UartSink::initialize() noexcept {
  write_register(uart::RegisterOffset::InterruptEnable, 0);
  write_register(uart::RegisterOffset::LineControl, LineControl::DlabEnable);

  constexpr std::uint32_t base_baud_rate = 115200;
  constexpr std::uint32_t target_baud    = 115200;

  static_assert(
      base_baud_rate % target_baud == 0,
      "Invalid baud rate requested"
  );
  constexpr std::uint16_t divisor =
      static_cast<std::uint16_t>(base_baud_rate / target_baud);

  write_register(uart::RegisterOffset::BaudRateLow, divisor & 0xff);
  write_register(uart::RegisterOffset::BaudRateHigh, (divisor >> 8) & 0xff);

  write_register(uart::RegisterOffset::LineControl, LineControl::DataSize8);
  write_register(
      uart::RegisterOffset::FifoController,
      FifoControl::Enable | FifoControl::ClearReceive |
          FifoControl::ClearTransmit | FifoControl::TriggerLevel4
  );

  write_register(
      uart::RegisterOffset::ModemControl,
      ModemControl::RequestToSend | ModemControl::DataTerminalReady |
          ModemControl::Out2
  );
}
}  // namespace x86_64
}  // namespace kernel