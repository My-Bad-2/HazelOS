#ifndef KERNEL_SYMBOLS_H
#define KERNEL_SYMBOLS_H 1

#include <stddef.h>
#include <stdint.h>

typedef struct {
    uint64_t addr;
    const char* name;
} kernel_symbol_t;

extern const kernel_symbol_t kernel_symbols[];
extern const size_t kernel_symbol_count;

const char* resolve_symbol(uintptr_t address, uintptr_t* offset);
void dump_stacktrace(void);

#endif