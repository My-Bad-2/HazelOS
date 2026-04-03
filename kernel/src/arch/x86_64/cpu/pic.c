#include "cpu/pic.h"

#include <stdint.h>

#include "cpu/exception.h"
#include "cpu/io.h"
#include "libs/log.h"

#define CASCADE_IRQ  2
#define PIC1_COMMAND 0x20
#define PIC1_DATA    0x21
#define PIC2_COMMAND 0xa0
#define PIC2_DATA    0xa1

#define ICW1_ICW4      0x01
#define ICW1_SINGLE    0x02
#define ICW1_INTERVAL4 0x04
#define ICW1_LEVEL     0x08
#define ICW1_INIT      0x10

#define ICW4_8086       0x01
#define ICW4_AUTO       0x02
#define ICW4_BUF_SLAVE  0x08
#define ICW4_BUF_MASTER 0x0c
#define ICW4_SFNM       0x10

#define PIC_EOI   0x20
#define PIC_ELCR1 0x4d0
#define PIC_ELCR2 0x4d1

static void pic_set_trigger_mode(uint8_t irq, irq_trigger_mode_t mode) {
    // only works for legacy hardwares
    uint16_t port = (irq < 8) ? PIC_ELCR1 : PIC_ELCR2;
    uint8_t bit   = (irq < 8) ? irq : (irq - 8);

    uint8_t val = io_read8(port);
    if (mode == IRQ_TRIGGER_LEVEL) {
        val |= (1 << bit);
    } else {
        val &= ~(1 << bit);
    }

    io_write8(port, val);
}

void pic_init(void) {
    io_write8(PIC1_COMMAND, ICW1_INIT | ICW1_ICW4);
    io_wait();
    io_write8(PIC2_COMMAND, ICW1_INIT | ICW1_ICW4);
    io_wait();

    // ICW2: Master PIC vector offset
    io_write8(PIC1_DATA, PLATFORM_INTERRUPT_BASE);
    io_wait();

    // ICW2: Slave PIC vector offset
    io_write8(PIC2_DATA, PLATFORM_INTERRUPT_BASE + 8);
    io_wait();

    // ICW3: tell Master PIC that there is a slave PIC at IRQ2
    io_write8(PIC1_DATA, 1 << CASCADE_IRQ);
    io_wait();

    // ICW3: tell Slave PIC its cascade identity (0000 0010)
    io_write8(PIC2_DATA, CASCADE_IRQ);
    io_wait();

    // ICW4: have the PICs use 8086 mode (and not 8080 mode)
    io_write8(PIC1_DATA, ICW4_8086);
    io_wait();
    io_write8(PIC2_DATA, ICW4_8086);
    io_wait();

    // Mask all interrupts for now
    pic_disable();
}

void pic_disable(void) {
    io_write8(PIC1_DATA, 0xff);
    io_write8(PIC2_DATA, 0xff);
}

void pic_configure_irq(uint8_t irq, bool mask, irq_trigger_mode_t mode) {
    irq -= PLATFORM_INTERRUPT_BASE;
    uint8_t port = (irq < 8) ? PIC1_DATA : PIC2_DATA;
    uint8_t bit  = (irq < 8) ? irq : (irq - 8);

    uint8_t val = io_read8(port);
    if (mask) {
        val |= (1 << bit);
    } else {
        val &= ~(1 << bit);
    }

    io_write8(port, val);

    pic_set_trigger_mode(irq, mode);

    KLOG_DEBUG(
        "PIC: configuring legacy vector mask:%d trigger_mode:%c\n",
        !!(mask),
        (mode == IRQ_TRIGGER_LEVEL) ? 'L' : 'E'
    );
}

void pic_send_eoi(uint8_t irq) {
    irq -= PLATFORM_INTERRUPT_BASE;

    if (irq >= 8) {
        io_write8(PIC2_COMMAND, PIC_EOI);
    }

    io_write8(PIC1_COMMAND, PIC_EOI);
}