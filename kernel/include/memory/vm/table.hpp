#include "memory/memory.hpp"
#ifndef KERNEL_MEMORY_VM_TABLE_HPP
#define KERNEL_MEMORY_VM_TABLE_HPP 1

#include <array>
#include <cstddef>
#include <string.h>
#include <type_traits>

#include "compiler.h"
#include "memory/vm/entry.hpp"

namespace kernel {
namespace memory {
class alignas(PAGE_SIZE_SMALL) PageTable {
 private:
  std::array<PageTableEntry, 512> m_entries;

 public:
  constexpr PageTable() noexcept = default;

  PageTable(const PageTable&)            = delete;
  PageTable& operator=(const PageTable&) = delete;

  __nodiscard constexpr PageTableEntry& operator[](std::size_t idx) noexcept {
    return m_entries[idx];
  }

  __nodiscard constexpr const PageTableEntry& operator[](
      size_t idx
  ) const noexcept {
    return m_entries[idx];
  }

  __nodiscard constexpr PageTableEntry* begin() noexcept {
    return m_entries.begin();
  }

  __nodiscard constexpr PageTableEntry* end() noexcept {
    return m_entries.end();
  }

  __nodiscard constexpr const PageTableEntry* begin() const noexcept {
    return m_entries.cbegin();
  }

  __nodiscard constexpr const PageTableEntry* end() const noexcept {
    return m_entries.cend();
  }

  void clear_range(std::size_t start, std::size_t end) noexcept {
    if (start >= 512 || end >= 512 || start > end) return;

    PageTableEntry* entries = begin();
    for (size_t i = start; i < end; ++i) entries->clear();
  }

  void clear_safe() noexcept {
    clear_range(0, 512);
  }

  void clear_entries() noexcept {
    memset(m_entries.data(), 0, m_entries.size());
  }
};

static_assert(sizeof(PageTable) == 4096, "PageTable must be exactly 4KB");
static_assert(alignof(PageTable) == 4096, "PageTable must be page-aligned");
static_assert(
    std::is_standard_layout_v<PageTable>,
    "PageTable must have standard C layout"
);
}  // namespace memory
}  // namespace kernel

#endif