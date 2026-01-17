#include "drivers/drivers.h"

#include "drivers/term.h"
#include "drivers/timer.h"

#include "internal/font.h"

void drivers_init(void) {
    timer_init();
    term_init(&term_font);
}