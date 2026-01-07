#define PIT_BASE_FREQ 1193182  // 1.193182 MHz
#define PIT_PORT_CH0  0x40     // Channel 0 Data Port (Read/Write)
#define PIT_PORT_CH1  0x41     // Channel 1 Data Port (Read/Write)
#define PIT_PORT_CH2  0x42     // Channel 2 Data Port (Read/Write)
#define PIT_PORT_CMD  0x43     // Mode/Command Register (Write Only)

#define PIT_PORT_GATE_CTRL 0x61

// Select Channel
#define PIT_SELECT_CH0 0x00
#define PIT_SELECT_CH1 0x40
#define PIT_SELECT_CH2 0x80
#define PIT_READ_BACK  0xC0

// Access Mode
#define PIT_ACCESS_LATCH 0x00  // Latch count value command
#define PIT_ACCESS_LO    0x10  // Access Mode: Low byte only
#define PIT_ACCESS_HI    0x20  // Access Mode: High byte only
#define PIT_ACCESS_LOHI  0x30  // Access Mode: Low byte + High byte

// Operating Mode
#define PIT_MODE_0 0x00  // Interrupt on terminal count
#define PIT_MODE_1 0x02  // Hardware re-triggerable one-shot
#define PIT_MODE_2 0x04  // Rate generator
#define PIT_MODE_3 0x06  // Square wave generator
#define PIT_MODE_4 0x08  // Software triggered strobe
#define PIT_MODE_5 0x0A  // Hardware triggered strobe

// BCD/Binary Mode
#define PIT_VAL_16BIT 0x00  // 16-bit Binary
#define PIT_VAL_BCD   0x01  // 4-digit BCD