#ifndef KERNEL_INCLUDE_CORE_CAPABILITY_CNODE_HPP
#define KERNEL_INCLUDE_CORE_CAPABILITY_CNODE_HPP 1

#include <cstdint>
#include <expected>
#include <new>

#include "core/capability/capability.hpp"
#include "core/capability/common.hpp"
#include "core/capability/cslot.hpp"

namespace kernel::core::capabilities {
struct alignas(std::hardware_destructive_interference_size) CNode {
  static constexpr std::size_t BITS_PER_LVL = 3;
  static constexpr std::size_t SLOT_COUNT   = 1 << BITS_PER_LVL;

  CSlot slots[SLOT_COUNT];

  __nodiscard CSlot& get_slot(std::uint8_t index) noexcept {
    __assume(index < SLOT_COUNT);
    return slots[index];
  }
};

template <std::size_t MaxDepth = 4>
__nodiscard std::expected<Capability, Error>
resolve_cspace(CNode* root, std::uint64_t cptr) noexcept {
  CNode* current = root;
  Capability cap;

#pragma GCC unroll 4
  for (std::size_t depth = 0; depth < MaxDepth; ++depth) {
    const std::size_t shift = 64 - ((depth + 1) * CNode::BITS_PER_LVL);
    const std::uint8_t index =
        static_cast<std::uint8_t>((cptr >> shift) & (CNode::SLOT_COUNT - 1));

    auto res = current->get_slot(index).validate();
    if (!res) [[unlikely]]
      return std::unexpected(res.error());

    cap = *res;

    if (cap.depth() > MaxDepth) [[unlikely]]
      return std::unexpected(Error::DEPTH_OVERFLOW);

    if (cap.type() != Capability::Type::CNODE) return cap;

    current = reinterpret_cast<CNode*>(cap.pointer());
  }

  return std::unexpected(Error::DEPTH_OVERFLOW);
}

template <std::size_t MaxDepth = 4>
__nodiscard std::expected<CSlot*, Error>
resolve_cspace_slot(CNode* root, std::uint64_t cptr) noexcept {
  CNode* current = root;
  Capability cap;

#pragma GCC unroll 4
  for (std::size_t depth = 0; depth < MaxDepth; ++depth) {
    const std::size_t shift = 64 - ((depth + 1) * CNode::BITS_PER_LVL);
    const std::uint8_t index =
        static_cast<std::uint8_t>((cptr >> shift) & (CNode::SLOT_COUNT - 1));

    CSlot* slot = &current->get_slot(index);

    if ((cptr & ((1ul << shift) - 1)) == 0 || depth == MaxDepth - 1)
      return slot;

    auto res = slot->validate();
    if (!res) [[unlikely]]
      return std::unexpected(res.error());
    cap = *res;

    if (cap.depth() > MaxDepth) [[unlikely]]
      return std::unexpected(Error::DEPTH_OVERFLOW);

    if (cap.type() != Capability::Type::CNODE)
      return std::unexpected(Error::TYPE_MISMATCH);

    current = reinterpret_cast<CNode*>(cap.pointer());
  }

  return std::unexpected(Error::DEPTH_OVERFLOW);
}
}  // namespace kernel::core::capabilities

#endif