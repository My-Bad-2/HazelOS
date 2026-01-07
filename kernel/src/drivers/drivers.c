#include "drivers/drivers.h"

#include "drivers/timer.h"

void drivers_init(void) {
    timer_init();
}