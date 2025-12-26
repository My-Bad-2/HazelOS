#ifndef KERNEL_LIBS_LOG_H
#define KERNEL_LIBS_LOG_H 1

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    LOG_TRACE = 0,  // Very noisy
    LOG_DEBUG,      // Standard debugging
    LOG_VERBOSE,    // Detailed Operational info
    LOG_INFO,       // General Operational info
    LOG_WARN,       // Warnings (non-fatal)
    LOG_ERROR,      // Errors (recoverable)
    LOG_FATAL       // Critical failures
} log_level_t;

// Set this to control what gets filtered out
#ifndef LOG_LEVEL_THRESHOLD
#define LOG_LEVEL_THRESHOLD LOG_TRACE
#endif

void kernel_log(log_level_t level, const char* file, int line, const char* fmt, ...);
[[noreturn]] void kernel_panic(const char* file, int line, const char* fmt, ...);

#define KLOG_TRACE(fmt, ...)   kernel_log(LOG_TRACE, __FILE_NAME__, __LINE__, fmt, ##__VA_ARGS__)
#define KLOG_DEBUG(fmt, ...)   kernel_log(LOG_DEBUG, __FILE_NAME__, __LINE__, fmt, ##__VA_ARGS__)
#define KLOG_VERBOSE(fmt, ...) kernel_log(LOG_VERBOSE, __FILE_NAME__, __LINE__, fmt, ##__VA_ARGS__)
#define KLOG_INFO(fmt, ...)    kernel_log(LOG_INFO, __FILE_NAME__, __LINE__, fmt, ##__VA_ARGS__)
#define KLOG_WARN(fmt, ...)    kernel_log(LOG_WARN, __FILE_NAME__, __LINE__, fmt, ##__VA_ARGS__)
#define KLOG_ERROR(fmt, ...)   kernel_log(LOG_ERROR, __FILE_NAME__, __LINE__, fmt, ##__VA_ARGS__)
#define KLOG_FATAL(fmt, ...)   kernel_log(LOG_FATAL, __FILE_NAME__, __LINE__, fmt, ##__VA_ARGS__)

#define PANIC(fmt, ...) kernel_panic(__FILE_NAME__, __LINE__, fmt, ##__VA_ARGS__)

#define ASSERT(exp)                          \
    if (!(exp)) {                            \
        PANIC("Assertion failed: %s", #exp); \
    }

#ifdef __cplusplus
}
#endif

#endif