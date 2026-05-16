#ifndef KERNEL_CORE_LOG_MANAGER_HPP
#define KERNEL_CORE_LOG_MANAGER_HPP 1

#include <array>

#include "core/log_sink.hpp"

namespace kernel {
namespace log {
struct LogConfig {
  bool enable_colors  = true;
  bool show_timestamp = true;
  bool show_subsystem = true;
  bool show_cpu_id    = true;
};

class LogManager {
 private:
  static constexpr std::size_t MAX_SINKS = 4;
  inline static std::array<LogSink*, MAX_SINKS> s_sinks{nullptr};
  inline static std::size_t s_sink_count{0};

  inline static LogConfig s_config{};

  static std::uint64_t get_uptime_ms() noexcept;
  static std::uint32_t get_cpu_id() noexcept;

  static std::string_view level_to_color(Level level) noexcept;

 public:
  static void set_config(const LogConfig& config) noexcept {
    s_config = config;
  }

  static bool add_sink(LogSink* sink) noexcept;

  static void dispatch(
      Level level,
      std::string_view subsystem,
      std::string_view message
  ) noexcept;
};
}  // namespace log
}  // namespace kernel

#endif