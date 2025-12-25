#include "boot/boot.h"

[[gnu::used]]
uint8_t bootstrap_stack[KSTACK_SIZE];

[[gnu::section(".requests")]]
volatile uint64_t limine_base_revision[] = LIMINE_BASE_REVISION(LIMINE_API_REVISION);

[[gnu::section(".requests_start")]]
volatile uint64_t limine_requests_start_marker[] = LIMINE_REQUESTS_START_MARKER;

[[gnu::section(".requests_end")]]
volatile uint64_t limine_requests_end_marker[] = LIMINE_REQUESTS_END_MARKER;