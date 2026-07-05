#include "core/capability/cslot.hpp"

#include <atomic>

#include "compiler.h"
#include "core/capability/capability.hpp"
#include "memory/address_space.hpp"

namespace kernel::core::capabilities {
std::expected<void, Error>
CSlot::insert(Capability cap, ParentGenerationNode* parent) noexcept {
  uint128_t expected = 0;
  uint128_t desired  = cap.raw();

  if (m_raw_capability.compare_exchange_strong(
          expected,
          desired,
          std::memory_order_acq_rel,
          std::memory_order_acquire
      )) {
    m_local_generation.store(cap.generation(), std::memory_order_release);
    m_parent_node.store(parent, std::memory_order_release);
    return {};
  }

  return std::unexpected(Error::SLOT_OCCUPIED);
}

std::expected<void, Error> CSlot::copy_to(CSlot& destination) noexcept {
  auto val_res = validate();
  if (!val_res) return std::unexpected(val_res.error());

  return destination.insert(
      *val_res,
      m_parent_node.load(std::memory_order_relaxed)
  );
}

std::expected<void, Error> CSlot::move_to(CSlot& dest) noexcept {
  uint128_t empty = 0;
  uint128_t raw_val =
      m_raw_capability.exchange(empty, std::memory_order_acq_rel);

  Capability cap(raw_val);
  if (cap.is_null()) [[unlikely]]
    return std::unexpected(Error::SLOT_EMPTY);

  if (m_local_generation.load(std::memory_order_acquire) != cap.generation())
      [[unlikely]] {
    m_local_generation.fetch_add(1, std::memory_order_relaxed);
    return std::unexpected(Error::GENERATION_MISMATCH);
  }

  ParentGenerationNode* p_node =
      m_parent_node.exchange(nullptr, std::memory_order_relaxed);

  if (p_node != nullptr) [[likely]] {
    if (p_node->master_generation.load(std::memory_order_acquire) > 1)
        [[unlikely]] {
      m_local_generation.fetch_add(1, std::memory_order_relaxed);
      p_node->active_child_count.fetch_sub(1, std::memory_order_release);
      return std::unexpected(Error::PARENT_REVOKED);
    }
  }

  auto dest_res = dest.insert(cap, p_node);
  if (!dest_res) [[unlikely]] {
    // Destination is occupied. We must put the capability back to the source.
    if (m_raw_capability.compare_exchange_strong(
            empty,
            raw_val,
            std::memory_order_acq_rel,
            std::memory_order_acquire
        )) {
      if (p_node)
        p_node->active_child_count.fetch_sub(1, std::memory_order_release);
      else
        m_parent_node.store(p_node, std::memory_order_release);
    }

    return dest_res;
  }

  m_local_generation.fetch_add(1, std::memory_order_release);
  return {};
}

void CSlot::clear() noexcept {
  uint128_t empty = 0;
  uint128_t old_raw =
      m_raw_capability.exchange(empty, std::memory_order_acq_rel);

  if (old_raw != 0) {
    Capability old_cap(old_raw);
    m_local_generation.fetch_add(1, std::memory_order_relaxed);

    ParentGenerationNode* p_node =
        m_parent_node.exchange(nullptr, std::memory_order_relaxed);
    if (p_node != nullptr)
      p_node->active_child_count.fetch_sub(1, std::memory_order_relaxed);

    if (old_cap.type() == Capability::Type::FRAME ||
        old_cap.type() == Capability::Type::PAGE_TABLE) {
      memory::kernel_space->dispatch_tlb_shootdown_context();
    }
  }
}
}  // namespace kernel::core::capabilities