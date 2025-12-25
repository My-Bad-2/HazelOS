#include "drivers/uart.h"

#include <stdint.h>

#include "arch.h"
#include "cpu/io.h"
#include "internals/uart.h"

static void uart_write(uint16_t port, uint16_t reg, uint8_t val) {
    io_write8(port + reg, val);
}

static uint8_t uart_read(uint16_t port, uint16_t reg) {
    return io_read8(port + reg);
}

static bool uart_is_tx_ready(uint16_t port) {
    return uart_read(port, UART_LINE_STATUS) & LINE_TRANSMITTER_BUF_EMPTY;
}

void drivers_uart_writec(uint16_t port, uint8_t ch) {
    while (!uart_is_tx_ready(port)) {
        arch_pause();
    }

    uart_write(port, UART_DATA, ch);
}

void drivers_uart_init(uint16_t port, uint32_t baud_rate) {
    // Disable all UART-generated interrupts; we use pure polling
    uart_write(port, UART_INTERRUPT, 0x00);

    // Enable Divisor Latch Access bit so we can program the baud rate
    uart_write(port, UART_LINE_CONTROL, LINE_DLAB_STATUS);

    // Calculate divisor: base clock (assumed 115200 Hz) / desired baud rate.
    uint32_t divisor = 115200 / baud_rate;

    uart_write(port, BAUD_RATE_LOW, divisor & 0xff);
    uart_write(port, BAUD_RATE_HIGH, (divisor >> 8) & 0xff);

    // Disable DLAB and set line to 8 data bits, no parity, 1 stop bit (8N1)
    uart_write(port, UART_LINE_CONTROL, LINE_DS_8);

    // Enable FIFO, clear both RX/TX queues, set highest trigger level.
    uart_write(
        port,
        FIFO_CONTROLLER,
        ENABLE_FIFO | FIFO_CLEAR_RECEIVE | FIFO_CLEAR_TRANSMIT | FIFO_TRIGGER_LEVEL4
    );

    // Enable RTS and DTR, and OUT2 (often required to enable interrupts)
    uart_write(port, UART_MODEM_CONTROL, MODEM_RTS | MODEM_DTR | MODEM_OUT2);
}