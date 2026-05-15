#ifndef KERNEL_CORE_LOG_SINK_HPP
#define KERNEL_CORE_LOG_SINK_HPP 1

#include <string_view>

namespace kernel {
namespace core {
class LogSink {
 public:
  LogSink(const LogSink&)            = delete;
  LogSink& operator=(const LogSink&) = delete;
  LogSink(LogSink&&)                 = delete;
  LogSink& operator=(LogSink&&)      = delete;

  void write(std::string_view str) noexcept {
    for (const char ch : str) {
      if (ch == '\n') transmit('\r');
      transmit(ch);
    }
  }

  void write(const char* str) noexcept {
    write(std::string_view{str});
  }

  void flush() noexcept {
    flush_fifo();
  }

  virtual ~LogSink() = default;

 protected:
  LogSink() = default;

 private:
  // Transmit a single raw byte to the hardware
  virtual void transmit(char ch) noexcept = 0;
  // Block until the pipeline is completely empty
  virtual void flush_fifo() noexcept = 0;
};
}  // namespace core
}  // namespace kernel

#endif