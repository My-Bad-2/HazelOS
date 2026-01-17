#include "drivers/drivers.h"

#include "drivers/term.h"
#include "drivers/timer.h"

void drivers_init(void) {
    timer_init();
    term_init();
}