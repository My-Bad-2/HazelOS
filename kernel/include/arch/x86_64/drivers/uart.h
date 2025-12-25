#ifndef KERNEL_DRIVERS_UART_H
#define KERNEL_DRIVERS_UART_H

#include <stdint.h>

#define COM_PORT1 0x3f8
#define COM_PORT2 0x2f8
#define COM_PORT3 0x3e8
#define COM_PORT4 0x2e8

void drivers_uart_writec(uint16_t port, uint8_t ch);
void drivers_uart_init(uint16_t port, uint32_t baud_rate);

#endif