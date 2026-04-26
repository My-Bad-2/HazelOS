#include "libs/symbols.h"

#include <stdint.h>
#include <stdio.h>

#include "arch.h"
#include "boot/boot.h"
#include "cpu/exception.h"

#define MAX_TRACE_DEPTH 32

struct stack_frame {
    struct stack_frame* next;  // Saved RBP
    uint64_t rip;              // Return address
};

extern char __isr_text_start[];
extern char __isr_text_end[];

static bool is_interrupt_stub(uint64_t rip) {
    return (rip >= (uint64_t)__isr_text_start && rip < (uint64_t)__isr_text_end);
}

static bool is_valid_frame(struct stack_frame* frame) {
    uint64_t addr = (uint64_t)frame;

    if (addr == 0) {
        return false;
    }

    if (addr % 8 != 0) {
        return false;
    }

    if (addr < hhdm_request.response->offset) {
        return false;
    }

    if (addr >= 0xFFFFFFFFFFFFF000) {
        return false;
    }

    return true;
}

static void trace_write(const char* msg) {
    arch_write(TARGET_UART, msg);
}

void dump_stacktrace(void) {
    struct stack_frame* frame;

    asm volatile("movq %%rbp, %0" : "=r"(frame));

    trace_write("\n\033[1;33m--- Kernel Call Trace ---\033[0m\n");

    int depth = 0;
    char buf[256];

    while (frame && depth < MAX_TRACE_DEPTH) {
        if (!is_valid_frame(frame)) {
            snprintf(
                buf,
                sizeof(buf),
                "  [%02d] <corrupted frame pointer: 0x%016lx>\n",
                depth,
                (uint64_t)frame
            );
            trace_write(buf);
            break;
        }

        uint64_t rip     = frame->rip;
        uint64_t offset  = 0;
        const char* name = resolve_symbol(rip, &offset);

        if (!name) {
            name = "???";
        }

        snprintf(buf, sizeof(buf), "  [%02d] [<0x%016lx>] %s+0x%lx\n", depth, rip, name, offset);
        trace_write(buf);

        if (is_interrupt_stub(rip)) {
            uint64_t stub_rbp = (uint64_t)frame->next;

            if (!is_valid_frame((struct stack_frame*)stub_rbp)) {
                trace_write("       <corrupted interrupt trapframe>\n");
                break;
            }

            struct interrupt_trapframe* trap = (struct interrupt_trapframe*)(stub_rbp + 8);
            uint64_t interrupted_rip         = trap->rip;

            uint64_t int_offset  = 0;
            const char* int_name = resolve_symbol(interrupted_rip, &int_offset);
            if (!int_name) {
                int_name = "???";
            }

            snprintf(
                buf,
                sizeof(buf),
                "       \033[31m|---> Interrupted at:\033[0m [<0x%016lx>] %s+0x%lx\n",
                interrupted_rip,
                int_name,
                int_offset
            );
            trace_write(buf);

            frame = (struct stack_frame*)trap->rbp;
        } else {
            frame = frame->next;
        }

        depth++;
    }

    if (depth == MAX_TRACE_DEPTH) {
        trace_write("  ... <trace truncated>\n");
    }

    trace_write("\033[1;33m-------------------------\033[0m\n");
}