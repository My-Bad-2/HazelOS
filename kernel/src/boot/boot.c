#include "boot/boot.h"

#include <stdint.h>

#include "boot/limine.h"

[[gnu::used]]
uint8_t bootstrap_stack[KSTACK_SIZE];

[[gnu::section(".requests"), gnu::used]]
volatile uint64_t limine_base_revision[] = LIMINE_BASE_REVISION(LIMINE_API_REVISION);

[[gnu::section(".requests_start"), gnu::used]]
volatile uint64_t limine_requests_start_marker[] = LIMINE_REQUESTS_START_MARKER;

[[gnu::section(".requests_end"), gnu::used]]
volatile uint64_t limine_requests_end_marker[] = LIMINE_REQUESTS_END_MARKER;

[[gnu::section(".requests"), gnu::used]]
volatile struct limine_memmap_request memmap_request = {
    .id       = LIMINE_MEMMAP_REQUEST_ID,
    .revision = 0,
    .response = nullptr,
};

[[gnu::section(".requests"), gnu::used]]
volatile struct limine_hhdm_request hhdm_request = {
    .id       = LIMINE_HHDM_REQUEST_ID,
    .revision = 0,
    .response = nullptr,
};

[[gnu::section(".requests"), gnu::used]]
volatile struct limine_mp_request mp_request = {
    .id       = LIMINE_MP_REQUEST_ID,
    .revision = 0,
    .response = nullptr,
#ifdef __x86_64__
    .flags = LIMINE_MP_REQUEST_X86_64_X2APIC,
#else
    .flags = 0
#endif
};