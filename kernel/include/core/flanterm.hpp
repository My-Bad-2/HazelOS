#ifndef KERNEL_INCLUDE_CORE_FLANTERM_HPP
#define KERNEL_INCLUDE_CORE_FLANTERM_HPP 1

#include "core/log_sink.hpp"
#include "flanterm.h"

namespace kernel {
namespace log {
class FlantermSink final : public LogSink {
 public:
  FlantermSink() = default;

  void initialize() noexcept;
  void write(std::string_view str) noexcept override;
  void flush() noexcept override;

 private:
  struct flanterm_context* m_ctx{nullptr};
};
}  // namespace log
}  // namespace kernel

#endif