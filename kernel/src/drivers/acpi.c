#include "drivers/acpi.h"

#include <errno.h>
#include <stdint.h>
#include <uacpi/context.h>

#include "drivers/madt.h"
#include "libs/log.h"
#include "memory/heap.h"
#include "uacpi/log.h"

void acpi_early_init(void) {
    KLOG_INIT_START("Early ACPI Tables");
    const size_t scratch_len = 64ul * 1024;
    uint8_t* buf             = kmalloc(scratch_len);

    if (!buf) {
        KLOG_INIT_FAIL();
        return;
    }

    uacpi_context_set_log_level(UACPI_LOG_WARN);
    uacpi_setup_early_table_access(buf, scratch_len);
    kfree(buf);

    if (!acpi_parse_tables()) {
        KLOG_INIT_FAIL();
        return;
    }

    KLOG_INIT_OK();
}