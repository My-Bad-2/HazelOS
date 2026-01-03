#include "drivers/acpi.h"

#include <errno.h>
#include <stdint.h>
#include <uacpi/context.h>
#include <uacpi/uacpi.h>

#include "drivers/madt.h"
#include "libs/log.h"
#include "memory/heap.h"

void acpi_early_init(void) {
    KLOG_INFO("ACPI: early init start\n");

    const size_t scratch_len = 1024 * sizeof(uint8_t);
    uint8_t* buf             = kmalloc(scratch_len);

    if (!buf) {
        errno = ENOMEM;
        KLOG_ERROR(
            "ACPI: failed to allocate early table buffer size=%zu errno=%d\n",
            scratch_len,
            errno
        );
        return;
    }

    uacpi_context_set_log_level(UACPI_LOG_DEBUG);
    uacpi_setup_early_table_access(buf, scratch_len);

    acpi_parse_tables();

    kfree(buf, scratch_len);

    KLOG_INFO("ACPI: early init complete\n");
}