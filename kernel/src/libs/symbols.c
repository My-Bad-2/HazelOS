#include "libs/symbols.h"

const char* resolve_symbol(uintptr_t address, uintptr_t* offset) {
    size_t left       = 0;
    size_t right      = kernel_symbol_count - 1;
    size_t best_index = SIZE_MAX;

    while (left <= right) {
        size_t mid = left + (right - left) / 2;

        if (kernel_symbols[mid].addr <= address) {
            best_index = mid;
            left       = mid + 1;
        } else {
            right = mid - 1;
        }
    }

    if (best_index != SIZE_MAX) {
        *offset = address - kernel_symbols[best_index].addr;
        return kernel_symbols[best_index].name;
    }

    *offset = 0;
    return "unknown";
}