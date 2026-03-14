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
    LOG_NOTICE,     // Normal but significant condition
    LOG_WARN,       // Warnings (non-fatal)
    LOG_ERROR,      // Errors (recoverable)
    LOG_CRIT,       // Critical conditions (e.g., hardware device failure)
    LOG_FATAL,      // Critical failures
    LOG_EMERG       // System is unusable
} log_level_t;

// Set this to control what gets filtered out
#ifndef LOG_LEVEL_THRESHOLD
#define LOG_LEVEL_THRESHOLD LOG_TRACE
#endif

void kernel_log(log_level_t level, const char* fmt, ...);
void kernel_log_cont(const char* fmt, ...);
[[noreturn]] void kernel_panic(const char* file, int line, const char* fmt, ...);

#define KLOG_TRACE(fmt, ...)   kernel_log(LOG_TRACE, fmt, ##__VA_ARGS__)
#define KLOG_DEBUG(fmt, ...)   kernel_log(LOG_DEBUG, fmt, ##__VA_ARGS__)
#define KLOG_VERBOSE(fmt, ...) kernel_log(LOG_VERBOSE, fmt, ##__VA_ARGS__)
#define KLOG_INFO(fmt, ...)    kernel_log(LOG_INFO, fmt, ##__VA_ARGS__)
#define KLOG_NOTICE(fmt, ...)  kernel_log(LOG_NOTICE, fmt, ##__VA_ARGS__)
#define KLOG_WARN(fmt, ...)    kernel_log(LOG_WARN, fmt, ##__VA_ARGS__)
#define KLOG_ERROR(fmt, ...)   kernel_log(LOG_ERROR, fmt, ##__VA_ARGS__)
#define KLOG_CRIT(fmt, ...)    kernel_log(LOG_CRIT, fmt, ##__VA_ARGS__)
#define KLOG_FATAL(fmt, ...)   kernel_log(LOG_FATAL, fmt, ##__VA_ARGS__)
#define KLOG_EMERG(fmt, ...)   kernel_log(LOG_EMERG, fmt, ##__VA_ARGS__)

#define KLOG_INIT_START(subsystem) kernel_log(LOG_INFO, "Initializing %s ... ", subsystem)
#define KLOG_INIT_OK()             kernel_log_cont("\033[32mOK\033[0m\n")
#define KLOG_INIT_FAIL()           kernel_log_cont("\033[31mFAILED\033[0m\n")

#define PANIC(fmt, ...) kernel_panic(__FILE_NAME__, __LINE__, fmt, ##__VA_ARGS__)

#if KERNEL_TEST
#define ASSERT(exp)                          \
    if (!(exp)) {                            \
        PANIC("Assertion failed: %s", #exp); \
    }
#else
#define ASSERT(exp) (void)0
#endif

#ifdef __cplusplus
}
#endif

#endif