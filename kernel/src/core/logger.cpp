#include "core/logger.hpp"

#include <stdio.h>
#include <string_view>

#include "core/log_manager.hpp"
#include "guards.hpp"
#include "hal/cpu.hpp"
#include "locks.hpp"

namespace kernel {
namespace log {
namespace {
MCSLock g_lock;
}

void Logger::format_and_dispatch(
    Level level,
    const char* fmt,
    std::va_list args
) const noexcept {
  const common::LockGuard _{g_lock};

  char buffer[256];

  const int length = vsnprintf(buffer, sizeof(buffer), fmt, args);

  if (length > 0) {
    const std::size_t len =
        (static_cast<std::size_t>(length) < sizeof(buffer)
             ? static_cast<std::size_t>(length)
             : sizeof(buffer) - 1);

    LogManager::dispatch(
        level,
        m_subsystem_name,
        std::string_view{buffer, len}
    );
  }
}

void Logger::trace(const char* fmt, ...) const noexcept {
  if (m_min_level > Level::Trace) return;
  std::va_list args;
  va_start(args, fmt);
  format_and_dispatch(Level::Trace, fmt, args);
  va_end(args);
}

void Logger::debug(const char* fmt, ...) const noexcept {
  if (m_min_level > Level::Debug) return;
  std::va_list args;
  va_start(args, fmt);
  format_and_dispatch(Level::Debug, fmt, args);
  va_end(args);
}

void Logger::info(const char* fmt, ...) const noexcept {
  if (m_min_level > Level::Info) return;
  std::va_list args;
  va_start(args, fmt);
  format_and_dispatch(Level::Info, fmt, args);
  va_end(args);
}

void Logger::error(const char* fmt, ...) const noexcept {
  if (m_min_level > Level::Error) return;
  std::va_list args;
  va_start(args, fmt);
  format_and_dispatch(Level::Error, fmt, args);
  va_end(args);
}

void Logger::warn(const char* fmt, ...) const noexcept {
  if (m_min_level > Level::Warning) return;
  std::va_list args;
  va_start(args, fmt);
  format_and_dispatch(Level::Warning, fmt, args);
  va_end(args);
}

void Logger::fatal(const char* fmt, ...) const noexcept {
  if (m_min_level > Level::Fatal) return;
  std::va_list args;
  va_start(args, fmt);
  format_and_dispatch(Level::Fatal, fmt, args);
  va_end(args);

  hal::cpu::halt(false);
}
}  // namespace log
}  // namespace kernel