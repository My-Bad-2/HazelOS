#ifndef KERNEL_ARCH_X86_64_CPU_HPP
#define KERNEL_ARCH_X86_64_CPU_HPP 1

#include <concepts>
#include <cstdint>
#include <type_traits>

namespace kernel {
namespace x86_64 {
namespace cpu {

// Must be an unsigned integer or an enum, and strictly <= 16 bits.
template <typename Tp>
concept PortNumber = (std::is_enum_v<Tp> || std::unsigned_integral<Tp>) &&
                     (sizeof(Tp) <= sizeof(std::uint16_t));

// x86 ports only support reading into 8-bit (al), 16-bit (ax), or 32-bit (eax)
// registers
template <typename Tp>
concept PortValue =
    std::same_as<Tp, std::uint8_t> || std::same_as<Tp, std::uint16_t> ||
    std::same_as<Tp, std::uint32_t>;

template <PortValue Tp>
inline Tp port_read(PortNumber auto port) {
  auto _port = static_cast<std::uint16_t>(port);
  Tp val;

  // GCC/Clang can automatically infer the correct instruction size and
  // accumulator register directly from the size of teh C++ variable bound to
  // %0.
  asm volatile("in %1, %0" : "=a"(val) : "Nd"(_port));
  return val;
}

template <PortValue Tp>
inline void port_write(PortNumber auto port, Tp val) {
  auto _port = static_cast<std::uint16_t>(port);

  asm volatile("out %0, %1" ::"a"(val), "Nd"(_port));
}
}  // namespace cpu
}  // namespace x86_64
}  // namespace kernel

#endif  // KERNEL_ARCH_X86_64_CPU_HPP