#include "libs/symbols.h"

#include <stdint.h>
#include <stdio.h>

#include "arch.h"
#include "boot/boot.h"
#include "cpu/exception.h"

struct stack_frame {
    struct stack_frame* next;  // Saved RBP
    uint64_t rip;              // Return address
};

extern char __isr_text_start[];
extern char __isr_text_end[];

static bool is_interrupt_stub(uint64_t rip) {
    return (rip >= (uint64_t)__isr_text_start && rip < (uint64_t)__isr_text_end);
}

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

        if (is_interrupt_stub(rip)) {
            // `frame` currently points to the RBP pushed by `isr_common_stub`. The stack address
            // above `frame` contains the `interrupt_trapframe_t`. However, `frame->next` points to
            // the saved RBP inside that struct. Hence, we calculate the pointer to the trapframe
            // based on the current rbp.
            uint64_t stub_rbp           = (uint64_t)frame->next;
            interrupt_trapframe_t* trap = (interrupt_trapframe_t*)(stub_rbp + 8);

            uint64_t interrupted_rip = trap->rip;

            const char* int_name = resolve_symbol(interrupted_rip, &offset);
            snprintf(
                buf,
                sizeof(buf),
                "[0x%lx] %s+0x%lx (Interrupted)\n",
                interrupted_rip,
                int_name,
                offset
            );

            arch_write(buf);

            frame = (struct stack_frame*)trap->rbp;
        } else {
            frame = frame->next;
        }

        depth++;
    }

    arch_write("------------------\n");
}