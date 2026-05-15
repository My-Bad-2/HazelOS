#include "arch/aarch64/core/uart.hpp"

#include <cstddef>
#include <cstdint>

#include "hal/io.hpp"

namespace kernel {
namespace aarch64 {
namespace {
// Data Register (UARTDR) & Receive Status Register (UARTRSR) Error Bits
// Bits [7:0] of UARTDR are the actual data payload.
struct DataError {
  static constexpr std::uint32_t Framing = (1 << 8);   // FE
  static constexpr std::uint32_t Parity  = (1 << 9);   // PE
  static constexpr std::uint32_t Break   = (1 << 10);  // BE
  static constexpr std::uint32_t Overrun = (1 << 11);  // OE
};

// Flag Register (UARTFR) Bits
struct Flag {
  static constexpr std::uint32_t ClearToSend       = (1 << 0);  // CTS
  static constexpr std::uint32_t DataSetReady      = (1 << 1);  // DSR
  static constexpr std::uint32_t DataCarrierDetect = (1 << 2);  // DCD
  static constexpr std::uint32_t Busy              = (1 << 3);  // BUSY
  static constexpr std::uint32_t ReceiveEmpty      = (1 << 4);  // RXFE
  static constexpr std::uint32_t TransmitFull      = (1 << 5);  // TXFF
  static constexpr std::uint32_t ReceiveFull       = (1 << 6);  // RXFF
  static constexpr std::uint32_t TransmitEmpty     = (1 << 7);  // TXFE
  static constexpr std::uint32_t RingIndicator     = (1 << 8);  // RI
};

// Line Control Register (UARTLCR_H) Bits
struct LineControl {
  static constexpr std::uint32_t SendBreak    = (1 << 0);  // BRK
  static constexpr std::uint32_t ParityEnable = (1 << 1);  // PEN
  static constexpr std::uint32_t ParityEven   = (1 << 2);  // EPS
  static constexpr std::uint32_t TwoStopBits  = (1 << 3);  // STP2
  static constexpr std::uint32_t FifoEnable   = (1 << 4);  // FEN

  // Word Length (WLEN) uses bits 5 and 6
  static constexpr std::uint32_t WordLength5 = (0 << 5);  // 0b00
  static constexpr std::uint32_t WordLength6 = (1 << 5);  // 0b01
  static constexpr std::uint32_t WordLength7 = (2 << 5);  // 0b10
  static constexpr std::uint32_t WordLength8 = (3 << 5);  // 0b11

  static constexpr std::uint32_t StickParity = (1 << 7);  // SPS
};

// Control Register (UARTCR) Bits
struct Control {
  static constexpr std::uint32_t UartEnable          = (1 << 0);   // UARTEN
  static constexpr std::uint32_t SirEnable           = (1 << 1);   // SIREN
  static constexpr std::uint32_t SirLowPower         = (1 << 2);   // SIRLP
  static constexpr std::uint32_t LoopbackEnable      = (1 << 7);   // LBE
  static constexpr std::uint32_t TransmitEnable      = (1 << 8);   // TXE
  static constexpr std::uint32_t ReceiveEnable       = (1 << 9);   // RXE
  static constexpr std::uint32_t DataTerminalReady   = (1 << 10);  // DTR
  static constexpr std::uint32_t RequestToSend       = (1 << 11);  // RTS
  static constexpr std::uint32_t Out1                = (1 << 12);  // Out1
  static constexpr std::uint32_t Out2                = (1 << 13);  // Out2
  static constexpr std::uint32_t RtsHardwareFlowCtrl = (1 << 14);  // RTSEN
  static constexpr std::uint32_t CtsHardwareFlowCtrl = (1 << 15);  // CTSEN
};

// Interrupt FIFO Level Select Register (UARTIFLS)
struct FifoLevelSelect {
  // Transmit Interrupt FIFO Level (Bits 0-2)
  static constexpr std::uint32_t TxLevel1_8 = (0 << 0);  // 1/8 full
  static constexpr std::uint32_t TxLevel1_4 = (1 << 0);  // 1/4 full
  static constexpr std::uint32_t TxLevel1_2 = (2 << 0);  // 1/2 full
  static constexpr std::uint32_t TxLevel3_4 = (3 << 0);  // 3/4 full
  static constexpr std::uint32_t TxLevel7_8 = (4 << 0);  // 7/8 full

  // Receive Interrupt FIFO Level (Bits 3-5)
  static constexpr std::uint32_t RxLevel1_8 = (0 << 3);  // 1/8 full
  static constexpr std::uint32_t RxLevel1_4 = (1 << 3);  // 1/4 full
  static constexpr std::uint32_t RxLevel1_2 = (2 << 3);  // 1/2 full
  static constexpr std::uint32_t RxLevel3_4 = (3 << 3);  // 3/4 full
  static constexpr std::uint32_t RxLevel7_8 = (4 << 3);  // 7/8 full
};

// Interrupt Registers (UARTIMSC, UARTRIS, UARTMIS, UARTICR)
// IMSC = Mask (Enable), RIS = Raw Status, MIS = Masked Status, ICR = Clear.
struct Interrupt {
  static constexpr std::uint32_t RingIndicator     = (1 << 0);   // RIMIM
  static constexpr std::uint32_t ClearToSend       = (1 << 1);   // CTSMIM
  static constexpr std::uint32_t DataCarrierDetect = (1 << 2);   // DCDMIM
  static constexpr std::uint32_t DataSetReady      = (1 << 3);   // DSRMIM
  static constexpr std::uint32_t Receive           = (1 << 4);   // RXIM
  static constexpr std::uint32_t Transmit          = (1 << 5);   // TXIM
  static constexpr std::uint32_t ReceiveTimeout    = (1 << 6);   // RTIM
  static constexpr std::uint32_t FramingError      = (1 << 7);   // FEIM
  static constexpr std::uint32_t ParityError       = (1 << 8);   // PEIM
  static constexpr std::uint32_t BreakError        = (1 << 9);   // BEIM
  static constexpr std::uint32_t OverrunError      = (1 << 10);  // OEIM

  static constexpr std::uint32_t All = 0x7ff;
};

// DMA Control Register (UARTDMACR)
struct DmaControl {
  static constexpr std::uint32_t ReceiveDmaEnable  = (1 << 0);  // RXDMAE
  static constexpr std::uint32_t TransmitDmaEnable = (1 << 1);  // TXDMAE
  static constexpr std::uint32_t DmaOnError        = (1 << 2);  // DMAONERR
};
}  // namespace

std::uint32_t UartSink::read_register(pl011::Register reg) const
    volatile noexcept {
  return hal::io::mmio_read(
      reinterpret_cast<volatile std::uint32_t*>(
          m_mmio_base + static_cast<std::uintptr_t>(reg)
      )
  );
}

void UartSink::write_register(
    pl011::Register reg,
    std::uint32_t val
) volatile noexcept {
  hal::io::mmio_write(
      reinterpret_cast<volatile std::uint32_t*>(
          m_mmio_base + static_cast<uintptr_t>(reg)
      ),
      val
  );
}

void UartSink::transmit(char ch) noexcept {
  wait_for_status<Flag::TransmitFull>();
  write_register(pl011::Register::Data, static_cast<std::uint32_t>(ch));
}

void UartSink::flush_fifo() noexcept {
  wait_for_status<Flag::Busy>();
}

void UartSink::initialize(
    std::uint64_t base_clock,
    std::uint32_t target_baud
) noexcept {
  write_register(pl011::Register::Control, 0);
  flush_fifo();

  const std::uint32_t lcr = read_register(pl011::Register::LineControl);
  write_register(pl011::Register::LineControl, lcr & ~LineControl::FifoEnable);

  write_register(pl011::Register::DMACR, 0);
  write_register(pl011::Register::InterruptClear, Interrupt::All);

  if (target_baud > 0 && base_clock > 0) {
    const std::uint64_t baud_div = (base_clock * 1000) / (16ul * target_baud);
    const auto ibrd              = static_cast<std::uint32_t>(baud_div / 1000);
    const auto fbrd =
        static_cast<std::uint32_t>((((baud_div % 1000) * 64) + 500) / 1000);

    write_register(pl011::Register::IntegerBaud, ibrd);
    write_register(pl011::Register::FractionBaud, fbrd);
  }

  write_register(
      pl011::Register::LineControl,
      LineControl::WordLength8 | LineControl::FifoEnable
  );
  write_register(pl011::Register::InterruptMask, 0);

  write_register(
      pl011::Register::Control,
      Control::UartEnable | Control::TransmitEnable | Control::ReceiveEnable
  );
}
}  // namespace aarch64
}  // namespace kernel