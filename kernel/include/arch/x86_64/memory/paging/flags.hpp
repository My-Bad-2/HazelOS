#ifndef KERNEL_ARCH_MEMORY_PAGING_FLAGS_HPP
#define KERNEL_ARCH_MEMORY_PAGING_FLAGS_HPP 1

#include <cstdint>
#include <utility>

#include "libs/maths.hpp"

namespace kernel {
namespace memory {
namespace arch {
enum class PageFlags : std::uint64_t {
  None         = 0,
  Present      = 1 << 0,
  Write        = 1 << 1,
  User         = 1 << 2,
  WriteThrough = 1 << 3,
  CacheDisable = 1 << 4,
  Accessed     = 1 << 5,
  Dirty        = 1 << 6,
  Huge         = 1 << 7,
  Global       = 1 << 8,
  NoExecute    = 1ul << 63,

  Pat      = 1 << 7,
  LargePat = 1 << 12,
};

enum class PatMemoryType : std::uint8_t {
  Uncacheable    = 0x00,  // UC (Strong Uncacheable)
  WriteCombining = 0x01,  // WC
  WriteThrough   = 0x04,  // WT
  WriteProtected = 0x05,  // WP
  WriteBack      = 0x06,  // WB
  UncachedWeak   = 0x07   // UC- (Can be overridden by MTRRs)
};

constexpr PageFlags operator|(PageFlags a, PageFlags b) noexcept {
  return static_cast<PageFlags>(std::to_underlying(a) | std::to_underlying(b));
}

constexpr PageFlags operator&(PageFlags a, PageFlags b) noexcept {
  return static_cast<PageFlags>(std::to_underlying(a) & std::to_underlying(b));
}

constexpr PageFlags operator~(PageFlags a) noexcept {
  return static_cast<PageFlags>(~std::to_underlying(a));
}

constexpr std::size_t PAGE_MASK = libs::maths::bit_mask<std::uint64_t>(52) &
                                  ~libs::maths::bit_mask<std::uint64_t>(12);
constexpr std::size_t PKEY_MASK = libs::maths::bit_mask<std::uint64_t>(59) &
                                  ~libs::maths::bit_mask<std::uint64_t>(55);

constexpr std::size_t MAX_ASID = 4096;
}  // namespace arch
}  // namespace memory
}  // namespace kernel

#endif  // KERNEL_ARCH_MEMORY_PAGING_FLAGS_HPP