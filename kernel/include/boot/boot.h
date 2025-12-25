#pragma once

#include "boot/limine.h"

#ifdef __cplusplus
extern "C" {
#endif

extern volatile struct limine_memmap_request memmap_request;
extern volatile struct limine_hhdm_request hhdm_request;

#ifdef __cplusplus
}
#endif