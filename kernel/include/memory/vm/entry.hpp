#include <cstdint>
#ifndef KERNEL_MEMORY_VM_ENTRY_HPP
#define KERNEL_MEMORY_VM_FLAGS_HPP 1

#include <type_traits>

#include "compiler.h"
#include "memory/address/physical.hpp"
#include "memory/paging/flags.hpp"
#include "memory/vm/flags.hpp"

namespace kernel {
namespace memory {
class PageTableEntry {
 private:
  std::uint64_t m_entry{0};
  static constexpr std::uint64_t FRAME_MASK = arch::PAGE_MASK;
  static constexpr std::uint64_t PKEY_MASK  = arch::PKEY_MASK;

 public:
  constexpr PageTableEntry() noexcept = default;

  __nodiscard std::uint64_t raw() const noexcept;
  __nodiscard bool is_present() const noexcept;
  __nodiscard bool has_flags(arch::PageFlags flags) const noexcept;
  __nodiscard PhysAddr get_frame() const noexcept;
  __nodiscard std::uint8_t get_pkey() const noexcept;
  __nodiscard std::size_t get_flags() const noexcept;

  void add_flags(arch::PageFlags flags) noexcept;
  void remove_flags(arch::PageFlags flags) noexcept;

  void set_frame(PhysAddr paddr) noexcept;
  void
  set(PhysAddr paddr, arch::PageFlags flags, std::uint8_t pkey = 0) noexcept;
  bool try_set_intermediate(
      PhysAddr paddr,
      arch::PageFlags flags,
      std::uint8_t pkey = 0
  ) noexcept;
  void clear() noexcept;
};

static_assert(
    sizeof(PageTableEntry) == sizeof(uint64_t),
    "PTE must be exactly 8 bytes"
);
static_assert(
    std::is_trivially_copyable_v<PageTableEntry>,
    "PTE must be trivially copyable"
);
static_assert(
    std::is_standard_layout_v<PageTableEntry>,
    "PTE must have standard C layout"
);
}  // namespace memory
}  // namespace kernel

#endif