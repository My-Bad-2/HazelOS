#include "libs/log.h"

#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

#include "arch.h"
#include "libs/spinlock.h"
#include "libs/symbols.h"

#define LOG_BUF_SIZE 1024  // 1KB buffer on stack

// Colors
static const char* C_RESET   = "\033[0m";
static const char* C_TRACE   = "\033[90m";     // Dark Grey
static const char* C_DEBUG   = "\033[36m";     // Cyan
static const char* C_VERBOSE = "\033[94m";     // Light Blue
static const char* C_INFO    = "\033[32m";     // Green
static const char* C_WARN    = "\033[33m";     // Yellow
static const char* C_ERROR   = "\033[31m";     // Red
static const char* C_FATAL   = "\033[41;37m";  // White on Red

static interrupt_lock_t log_lock;

static void get_level_meta(log_level_t level, const char** color, const char** label) {
    switch (level) {
        case LOG_TRACE:
            *color = C_TRACE;
            *label = "TRACE";
            break;
        case LOG_DEBUG:
            *color = C_DEBUG;
            *label = "DEBUG";
            break;
        case LOG_VERBOSE:
            *color = C_VERBOSE;
            *label = "VERB ";
            break;
        case LOG_INFO:
            *color = C_INFO;
            *label = "INFO ";
            break;
        case LOG_WARN:
            *color = C_WARN;
            *label = "WARN ";
            break;
        case LOG_ERROR:
            *color = C_ERROR;
            *label = "ERROR";
            break;
        case LOG_FATAL:
            *color = C_FATAL;
            *label = "FATAL";
            break;
        default:
            *color = C_RESET;
            *label = "UNK  ";
            break;
    }
}

void kernel_log(log_level_t level, const char* file, int line, const char* fmt, ...) {
    if (level < LOG_LEVEL_THRESHOLD) {
        return;
    }

    char buf[LOG_BUF_SIZE];
    const char* color;
    const char* label;

    get_level_meta(level, &color, &label);

    int offset = snprintf(buf, LOG_BUF_SIZE, "%s[%s] %s:%d: ", color, label, file, line);

    // Safety check for buffer overflow
    if (offset < 0) {
        offset = 0;
    }

    if (offset >= LOG_BUF_SIZE) {
        offset = LOG_BUF_SIZE - 1;
    }

    va_list args;
    va_start(args, fmt);
    int body_len = vsnprintf(buf + offset, (size_t)(LOG_BUF_SIZE - offset), fmt, args);
    va_end(args);

    int total_len = offset + body_len;

    if (total_len >= LOG_BUF_SIZE - 5) {
        total_len = LOG_BUF_SIZE - 5;
    }

    for (int i = 0; i < 5; ++i) {
        buf[total_len++] = C_RESET[i];
    }

    buf[total_len] = '\0';

    acquire_interrupt_lock(&log_lock);
    arch_write(buf);
    release_interrupt_lock(&log_lock);
}

void kernel_panic(const char* file, int line, const char* fmt, ...) {
    // Disable interrupts immediately
    arch_disable_interrupts();

    // Same color as LOG_FATAL
    arch_write("\n\033[41;37m!!! KERNEL PANIC !!!\033[0m\n");

    char buf[64];
    snprintf(buf, 64, "Location: %s:%d\n", file, line);
    arch_write(buf);

    arch_write("Reason:   ");

    va_list args;
    va_start(args, fmt);

    // We use a local buffer. If the stack is corrupted, this might fail,
    // but it's safer than relying on global buffers.
    char msg_buf[256];
    vsnprintf(msg_buf, sizeof(msg_buf), fmt, args);
    va_end(args);

    arch_write(msg_buf);

#if KERNEL_TEST
    dump_stacktrace();
#endif

    arch_write("\nSystem Halted.\n");

    arch_halt(false);
}