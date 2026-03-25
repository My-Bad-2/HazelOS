#include "libs/log.h"

#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

#include "arch.h"
#include "cpu/smp.h"
#include "drivers/timer.h"
#include "libs/spinlock.h"
#include "libs/symbols.h"

#define LOG_BUF_SIZE 1024  // 1KB buffer on stack

// Colors
static const char* C_RESET   = "\033[0m";
static const char* C_TRACE   = "\033[90m";       // Dark Grey
static const char* C_DEBUG   = "\033[36m";       // Cyan
static const char* C_VERBOSE = "\033[94m";       // Light Blue
static const char* C_INFO    = "\033[32m";       // Green
static const char* C_NOTICE  = "\033[1;32m";     // Bold Green
static const char* C_WARN    = "\033[33m";       // Yellow
static const char* C_ERROR   = "\033[31m";       // Red
static const char* C_CRIT    = "\033[1;31m";     // Bold Red
static const char* C_FATAL   = "\033[41;37m";    // White on Red Background
static const char* C_EMERG   = "\033[5;41;37m";  // Blinking White on Red

static spinlock_t log_lock;

static uint32_t last_cpu_id          = 0;
static bool line_is_unterminated     = false;
static log_level_t last_target_level = LOG_LEVEL_THRESHOLD;
static bool panic_in_progress        = false;

static void get_level_meta(log_level_t level, const char** color, const char** label) {
    if (!color || !label) {
        arch_halt(false);
    }

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
        case LOG_NOTICE:
            *color = C_NOTICE;
            *label = "NOTIC";
            break;
        case LOG_WARN:
            *color = C_WARN;
            *label = "WARN ";
            break;
        case LOG_ERROR:
            *color = C_ERROR;
            *label = "ERROR";
            break;
        case LOG_CRIT:
            *color = C_CRIT;
            *label = "CRIT ";
            break;
        case LOG_FATAL:
            *color = C_FATAL;
            *label = "FATAL";
            break;
        case LOG_EMERG:
            *color = C_EMERG;
            *label = "EMERG";
            break;
        default:
            *color = C_RESET;
            *label = "UNK  ";
            break;
    }
}

static uint8_t determine_targets(log_level_t level) {
    if (level >= LOG_WARN) {
        return TARGET_UART;
    }

    return TARGET_FRAMEBUFFER;
}

static void dispatch_write(const char* str, log_level_t level) {
    arch_write(determine_targets(level), str);
}

void kernel_log(log_level_t level, const char* fmt, ...) {
    if (level < LOG_LEVEL_THRESHOLD) {
        return;
    }

    char buf[LOG_BUF_SIZE];
    const char* color;
    const char* label;

    get_level_meta(level, &color, &label);

    uint32_t cpu_id = arch_get_core_idx();
    size_t ms       = timer_get_time_ms();

    int offset =
        snprintf(buf, LOG_BUF_SIZE, "%s[%6lu.%03lu] [%s]: ", color, ms / 1000, ms % 1000, label);
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

    for (int i = 0; i < 4; ++i) {
        buf[total_len++] = C_RESET[i];
    }
    buf[total_len] = '\0';

    bool ends_with_newline = (buf[total_len - 5] == '\n');

    size_t flags = 0;
    if (!panic_in_progress) {
        flags = acquire_interrupt_lock(&log_lock);
    }

    if (line_is_unterminated && last_cpu_id != cpu_id) {
        dispatch_write(C_RESET, level);
        dispatch_write("\n", level);
    }

    dispatch_write(buf, level);

    last_cpu_id          = cpu_id;
    last_target_level    = level;
    line_is_unterminated = !ends_with_newline;

    if (!panic_in_progress) {
        release_interrupt_lock(&log_lock, flags);
    }
}

void kernel_log_cont(const char* fmt, ...) {
    char buf[LOG_BUF_SIZE];

    va_list args;
    va_start(args, fmt);
    int len = vsnprintf(buf, LOG_BUF_SIZE, fmt, args);
    va_end(args);

    if (len >= LOG_BUF_SIZE) len = LOG_BUF_SIZE - 1;
    bool ends_with_newline = (buf[len - 1] == '\n');

    uint32_t cpu_id = arch_get_core_idx();

    size_t flags = 0;
    if (!panic_in_progress) {
        flags = acquire_interrupt_lock(&log_lock);
    }

    log_level_t level = last_target_level;
    if (last_cpu_id != cpu_id && last_cpu_id != -1) {
        char rescue_buf[64];
        snprintf(rescue_buf, sizeof(rescue_buf), "\n[CPU%02d] (cont): ", cpu_id);
        dispatch_write(rescue_buf, level);
    }

    dispatch_write(buf, level);

    last_cpu_id          = cpu_id;
    line_is_unterminated = !ends_with_newline;

    if (!panic_in_progress) {
        release_interrupt_lock(&log_lock, flags);
    }
}

void kernel_panic(const char* file, int line, const char* fmt, ...) {
    arch_disable_interrupts();

    panic_in_progress = true;

    dispatch_write("\n\033[5;41;37m!!! KERNEL PANIC !!!\033[0m\n", LOG_EMERG);

    char buf[128];
    snprintf(buf, sizeof(buf), "Location: %s:%d\nReason:   ", file, line);
    dispatch_write(buf, LOG_EMERG);

    va_list args;
    va_start(args, fmt);
    char msg_buf[256];
    vsnprintf(msg_buf, sizeof(msg_buf), fmt, args);
    va_end(args);

    dispatch_write(msg_buf, LOG_EMERG);
    dispatch_write("\n", LOG_EMERG);

#if KERNEL_TEST
    dump_stacktrace();
#endif

    dispatch_write("\nSystem Halted.\n", LOG_EMERG);
    smp_send_panic_ipi();
    arch_halt(false);
}