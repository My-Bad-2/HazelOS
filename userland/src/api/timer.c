#include "api/timer.h"

#include "syscall.h"

int timer_create(uint64_t* cap_out) {
    return syscall(SYS_TIMER_CREATE, (long)cap_out);
}

int timer_cancel(uint64_t timer_cap) {
    return syscall(SYS_TIMER_CANCEL, (long)timer_cap);
}

int timer_set(uint64_t timer_cap, uint64_t delay_ns, uint64_t interval_ns) {
    return syscall(SYS_TIMER_SET, (long)timer_cap, (long)delay_ns, (long)interval_ns);
}