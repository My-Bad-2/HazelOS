#include "libs/symbols.h"

#include <stdio.h>

#include "arch.h"
#include "boot/boot.h"

struct stack_frame {
    struct stack_frame* next;  // Saved RBP
    uint64_t rip;              // Return address
};

void dump_stacktrace(void) {
    struct stack_frame* frame;

    asm volatile("movq %%rbp, %0" : "=r"(frame));

    arch_write("\n--- CALL TRACE ---\n");

    int depth = 0;

    while (frame && depth < 20) {
        if ((uint64_t)frame < hhdm_request.response->offset) {
            break;
        }

        uint64_t rip     = frame->rip;
        uint64_t offset  = 0;
        const char* name = resolve_symbol(rip, &offset);

        char buf[128];
        snprintf(buf, sizeof(buf), "[0x%lx] %s+0x%lx\n", rip, name, offset);
        arch_write(buf);

        frame = frame->next;
        depth++;
    }

    arch_write("------------------\n");
}