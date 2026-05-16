#include "core/log_manager.hpp"

#include <cstdint>
#include <stdio.h>
#include <string_view>

namespace kernel {
namespace log {
std::string_view LogManager::level_to_color(Level level) noexcept {
  switch (level) {
    case Level::Trace:
      return "\033[37m";  // White
    case Level::Debug:
      return "\033[36m";  // Cyan
    case Level::Info:
      return "\033[32m";  // Green
    case Level::Warning:
      return "\033[33m";  // Yellow
    case Level::Error:
      return "\033[31m";  // Red
    case Level::Fatal:
      return "\033[41;37m";  // White on Red
    default:
      return "";
  }
}

std::uint64_t LogManager::get_uptime_ms() noexcept {
  return 0;
}

std::uint32_t LogManager::get_cpu_id() noexcept {
  return 0;
}

bool LogManager::add_sink(LogSink* sink) noexcept {
  if (s_sink_count >= MAX_SINKS) return false;
  s_sinks[s_sink_count++] = sink;
  return true;
}

void LogManager::dispatch(
    Level level,
    std::string_view subsystem,
    std::string_view message
) noexcept {
  if (s_sink_count == 0) return;

  char prefix_buf[128] = {0};
  int prefix_len       = 0;

  if (s_config.show_timestamp)
    prefix_len += snprintf(
        prefix_buf + prefix_len,
        sizeof(prefix_buf) - static_cast<std::size_t>(prefix_len),
        "[%8llu] ",
        get_uptime_ms()
    );

  if (s_config.show_cpu_id)
    prefix_len += snprintf(
        prefix_buf + prefix_len,
        sizeof(prefix_buf) - static_cast<std::size_t>(prefix_len),
        "[Cpu%u] ",
        get_cpu_id()
    );

  if (s_config.show_subsystem)
    prefix_len += snprintf(
        prefix_buf + prefix_len,
        sizeof(prefix_buf) - static_cast<std::size_t>(prefix_len),
        "[%-4s] ",
        // NOLINTNEXTLINE
        subsystem.data()
    );

  const std::string_view prefix_view{
      prefix_buf,
      sizeof(prefix_buf) - static_cast<std::size_t>(prefix_len)
  };

  const std::string_view color_prefix =
      s_config.enable_colors ? level_to_color(level) : "";
  const std::string_view color_reset = s_config.enable_colors ? "\033[0m" : "";

  for (std::size_t i = 0; i < s_sink_count; ++i) {
    LogSink* sink = s_sinks[i];

    if (level < sink->get_level()) continue;

    sink->write(color_prefix);
    sink->write(prefix_view);
    sink->write(message);
    sink->write(color_reset);
    sink->write("\r\n");

    if (level == Level::Fatal) sink->flush();
  }
}
}  // namespace log
}  // namespace kernel