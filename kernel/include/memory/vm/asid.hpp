#ifndef KERNEL_INCLUDE_MEMORY_VM_ASID_HPP
#define KERNEL_INCLUDE_MEMORY_VM_ASID_HPP 1

#include <cstdint>
#include <utility>

#include "compiler.h"
#include "memory/paging/flags.hpp"

namespace kernel {
namespace memory {
using TlbFlushCallback = void (*)() noexcept;
using CacheEntry       = std::pair<std::uint16_t, std::uint64_t>;

class AsidManager {
 private:
  std::uint16_t m_next_asid   = 1;  // ASID 0 is reserved for kernel
  std::size_t m_current_epoch = 1;

  TlbFlushCallback m_flush_hw = nullptr;

 public:
  constexpr AsidManager() noexcept = default;

  void initialize(TlbFlushCallback hw_flusher) noexcept {
    m_flush_hw = hw_flusher;
  }

  __nodiscard std::pair<std::uint16_t, std::size_t> allocate() noexcept {
    if (m_next_asid >= arch::MAX_ASID) {
      m_next_asid = 1;
      m_current_epoch++;

      if (m_flush_hw) m_flush_hw();
    }

    return std::make_pair(m_next_asid++, m_current_epoch);
  }

  __nodiscard std::size_t get_epoch() const noexcept {
    return m_current_epoch;
  }
};

AsidManager& get_current_asid_manager() noexcept;
}  // namespace memory
}  // namespace kernel

#endif