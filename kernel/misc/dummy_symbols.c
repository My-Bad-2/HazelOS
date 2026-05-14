#include <stddef.h>
#include <stdint.h>

typedef struct {
    uint64_t addr;
    const char* name;
} kernel_symbol_t;

const kernel_symbol_t kernel_symbols[] = {{0, ""}};

const size_t kernel_symbol_count = 0;