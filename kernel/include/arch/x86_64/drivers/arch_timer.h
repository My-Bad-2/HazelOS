#ifndef KERNEL_DRIVERS_ARCH_TIMER_H
#define KERNEL_DRIVERS_ARCH_TIMER_H 1

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    CLOCK_PIT,
    // CLOCK_HPET,
    // CLOCK_LAPIC,
} clock_source_t;

typedef enum {
    TIMER_ONESHOT,
    TIMER_PERIODIC,
    TIMER_TSC_DEADLINE,
} timer_type_t;

#ifdef __cplusplus
}
#endif

#endif