#include <string.h>

#include "arch.h"

void kmain() {
    arch_serial_init();

    const char* msg = "Hello, World!\n";
    size_t len      = strlen(msg);
    arch_write(msg, len);

    arch_halt(true);
}