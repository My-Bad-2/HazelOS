#include "memory/vmm.h"

#include "boot/boot.h"
#include "memory/pagemap.h"

pagemap_t kernel_pagemap;

pagemap_t* vmm_get_kernel_pagemap() {
    return &kernel_pagemap;
}

void vmm_init(void) {
    pagemap_create(&kernel_pagemap);

    uintptr_t kernel_base = (uintptr_t)kernel_file_request.response->executable_file->address;

    uintptr_t phys_base = kernel_address_request.response->physical_base;
    uintptr_t virt_base = kernel_address_request.response->virtual_base;

    uintptr_t phys_delta = phys_base - virt_base;

    vmm_map_kernel(&kernel_pagemap, kernel_base, phys_delta);
    pagemap_load(&kernel_pagemap);
}