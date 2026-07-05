#include <expected>
#ifndef KERNEL_INCLUDE_CORE_CAPABILITY_CSLOT_HPP
#define KERNEL_INCLUDE_CORE_CAPABILITY_CSLOT_HPP 1

#include <atomic>
#include <cstdint>
#include <new>

#include "compiler.h"
#include "core/capability/capability.hpp"

namespace kernel::core::capabilities {
static_assert(
    std::atomic<uint128_t>::is_always_lock_free,
    "Compiler failed to generate lock-free CMPXCHG16B!"
);

struct alignas(16) ParentGenerationNode {
  std::atomic<std::uint32_t> master_generation{1};
  std::atomic<std::uint32_t> active_child_count{0};
  std::uintptr_t phys_base_addr;
};

class alignas(std::hardware_destructive_interference_size) CSlot {
 private:
  std::atomic<uint128_t> m_raw_capability{0};
  std::atomic<std::uint16_t> m_local_generation{0};
  std::atomic<ParentGenerationNode*> m_parent_node{nullptr};

 public:
  template <typename Self>
  __nodiscard std::expected<Capability, Error> validate(
      this Self&& self
  ) noexcept {
    uint128_t raw_val = self.m_raw_capability.load(std::memory_order_acquire);

    Capability cap(raw_val);

    if (cap.is_null()) [[unlikely]]
      return std::unexpected(Error::SLOT_EMPTY);

    if (self.m_local_generation.load(std::memory_order_acquire) !=
        cap.generation()) [[unlikely]]
      return std::unexpected(Error::GENERATION_MISMATCH);

    ParentGenerationNode* p_node =
        self.m_parent_node.load(std::memory_order_acquire);
    if (p_node != nullptr) [[likely]] {
      if (p_node->master_generation.load(std::memory_order_acquire) > 1)
          [[unlikely]] {
        self.clear();
        return std::unexpected(Error::PARENT_REVOKED);
      }
    }

    return cap;
  }

  std::expected<void, Error>
  insert(Capability cap, ParentGenerationNode* parent = nullptr) noexcept;
  std::expected<void, Error> copy_to(CSlot& destination) noexcept;
  std::expected<void, Error> move_to(CSlot& dest) noexcept;

  void clear() noexcept;
};
}  // namespace kernel::core::capabilities

#endif