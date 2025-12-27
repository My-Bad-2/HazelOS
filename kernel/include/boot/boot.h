#ifndef KERNEL_BOOT_BOOT_H
#define KERNEL_BOOT_BOOT_H 1

#include "boot/limine.h"

#ifdef __cplusplus
extern "C" {
#endif

extern volatile struct limine_memmap_request memmap_request;
extern volatile struct limine_hhdm_request hhdm_request;
extern volatile struct limine_mp_request mp_request;
extern volatile struct limine_executable_address_request kernel_address_request;
extern volatile struct limine_executable_file_request kernel_file_request;

#ifdef __cplusplus
}
#endif

#endif