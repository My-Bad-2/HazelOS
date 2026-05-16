#ifndef KERNEL_CORE_LOG_HPP
#define KERNEL_CORE_LOG_HPP 1

#include <cstdint>
#include <string_view>

#include "compiler.h"

namespace kernel {
namespace log {
enum class Level : std::uint8_t { Trace, Debug, Info, Warning, Error, Fatal };

class LogSink {
 public:
  virtual ~LogSink() = default;

  virtual void write(std::string_view str) noexcept = 0;

  virtual void flush() noexcept = 0;

  void set_level(Level min_level) noexcept {
    m_min_level = min_level;
  }

  __nodiscard Level get_level() const noexcept {
    return m_min_level;
  }

 protected:
  LogSink() = default;

 private:
  Level m_min_level{Level::Trace};
};
}  // namespace log
}  // namespace kernel

#endif