#ifndef KERNEL_MEMORY_VM_FLAGS_HPP
#define KERNEL_MEMORY_VM_FLAGS_HPP 1

#include <cstdint>
#include <utility>

namespace kernel {
namespace memory {
enum class VmFlags : std::uint8_t {
  None    = 0,
  Read    = 1 << 0,
  Write   = 1 << 1,
  Execute = 1 << 2,
  User    = 1 << 3,
  Global  = 1 << 4,
  Huge    = 1 << 5
};

constexpr VmFlags operator|(VmFlags a, VmFlags b) noexcept {
  return static_cast<VmFlags>(std::to_underlying(a) | std::to_underlying(b));
}

constexpr VmFlags operator&(VmFlags a, VmFlags b) noexcept {
  return static_cast<VmFlags>(std::to_underlying(a) & std::to_underlying(b));
}

constexpr VmFlags operator~(VmFlags a) noexcept {
  return static_cast<VmFlags>(~std::to_underlying(a));
}

enum class CacheMode : std::uint8_t {
  Uncacheable,
  UncacheableStrong,
  WriteThrough,
  WriteProtected,
  WriteCombining,
  WriteBack,
};
}  // namespace memory
}  // namespace kernel

#endif