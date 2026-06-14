#ifndef KERNEL_CORE_LOGGER_HPP
#define KERNEL_CORE_LOGGER_HPP 1

#include <cstdarg>

#include "compiler.h"
#include "core/log_sink.hpp"

namespace kernel {
namespace log {
class Logger {
 private:
  const char* m_subsystem_name;
  Level m_min_level;

  void format_and_dispatch(
      Level level,
      const char* fmt,
      std::va_list args
  ) const noexcept;

 public:
  constexpr explicit Logger(
      const char* subsystem_name,
      Level min_level = Level::Info
  ) noexcept
      : m_subsystem_name(subsystem_name), m_min_level(min_level) {}

  void set_level(Level level) noexcept {
    m_min_level = level;
  }

  __printf(2, 3) void trace(const char* fmt, ...) const noexcept;
  __printf(2, 3) void debug(const char* fmt, ...) const noexcept;
  __printf(2, 3) void info(const char* fmt, ...) const noexcept;
  __printf(2, 3) void warn(const char* fmt, ...) const noexcept;
  __printf(2, 3) void error(const char* fmt, ...) const noexcept;
  __printf(2, 3) void fatal(const char* fmt, ...) const noexcept;
};
}  // namespace log
}  // namespace kernel

#endif  // KERNEL_CORE_LOGGER_HPP