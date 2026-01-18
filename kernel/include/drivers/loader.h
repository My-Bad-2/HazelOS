#ifndef KERNEL_DRIVERS_LOADER_H
#define KERNEL_DRIVERS_LOADER_H 1

#include "sched/process.h"

#ifdef __cplusplus
extern "C" {
#endif

thread_t* load_elf(void* address);
void launch_user_init(void);

#ifdef __cplusplus
}
#endif

#endif