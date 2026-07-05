#include "core/capabilities.hpp"

#include <atomic>
#include <expected>

#include "compiler.h"
#include "core/capability/capability.hpp"
#include "core/capability/cnode.hpp"
#include "core/capability/common.hpp"
#include "memory/address/physical.hpp"
#include "memory/address/virtual.hpp"

namespace kernel::core::capabilities {
std::expected<void, Error> Dispatcher::copy(
    CNode* root,
    std::uint64_t src_cptr,
    std::uint64_t dest_cptr
) noexcept {
  auto src_slot_res = resolve_cspace_slot(root, src_cptr);
  if (!src_slot_res) [[unlikely]]
    return std::unexpected(src_slot_res.error());

  auto dest_slot_res = resolve_cspace_slot(root, dest_cptr);
  if (!dest_slot_res) [[unlikely]]
    return std::unexpected(dest_slot_res.error());

  return (*src_slot_res)->copy_to(*(*dest_slot_res));
}

std::expected<void, Error> Dispatcher::move(
    CNode* root,
    std::uint64_t src_cptr,
    std::uint64_t dest_cptr
) noexcept {
  auto src_slot_res = resolve_cspace_slot(root, src_cptr);
  if (!src_slot_res) [[unlikely]]
    return std::unexpected(src_slot_res.error());

  auto dest_slot_res = resolve_cspace_slot(root, dest_cptr);
  if (!dest_slot_res) [[unlikely]]
    return std::unexpected(dest_slot_res.error());

  return (*src_slot_res)->move_to(*(*dest_slot_res));
}

std::expected<void, Error> Dispatcher::mint(
    CNode* root,
    std::uint64_t src_cptr,
    std::uint64_t dest_cptr,
    CapRights new_rights,
    std::uint32_t new_badge
) noexcept {
  auto src_slot_res = resolve_cspace_slot(root, src_cptr);
  if (!src_slot_res) [[unlikely]]
    return std::unexpected(src_slot_res.error());

  auto dest_slot_res = resolve_cspace_slot(root, dest_cptr);
  if (!dest_slot_res) [[unlikely]]
    return std::unexpected(dest_slot_res.error());

  auto val_res = (*src_slot_res)->validate();
  if (!val_res) [[unlikely]]
    return std::unexpected(val_res.error());

  auto minted_cap = val_res->mint(new_rights, new_badge);
  if (!minted_cap) [[unlikely]]
    return std::unexpected(minted_cap.error());

  return (*dest_slot_res)->insert(*minted_cap, nullptr);
}

std::expected<void, Error>
Dispatcher::erase(CNode* root, std::uint64_t target_cptr) noexcept {
  auto target_slot_res = resolve_cspace_slot(root, target_cptr);
  if (!target_slot_res) [[unlikely]]
    return std::unexpected(target_slot_res.error());

  (*target_slot_res)->clear();
  return {};
}

std::expected<void, Error>
Dispatcher::revoke(CNode* root, std::uint64_t target_cptr) noexcept {
  auto target_slot_res = resolve_cspace_slot(root, target_cptr);
  if (!target_slot_res) [[unlikely]]
    return std::unexpected(target_slot_res.error());

  auto val_res = (*target_slot_res)->validate();
  if (!val_res) [[unlikely]]
    return std::unexpected(val_res.error());

  if (!has_rights(val_res->rights(), CapRights::REVOKE))
    return std::unexpected(Error::INSUFFICIENT_RIGHTS);

  if (val_res->type() == Capability::Type::UNTYPED) {
    memory::PhysAddr p_addr{val_res->pointer()};

    auto* p_node = p_addr.to_virt().as<ParentGenerationNode>();

    p_node->master_generation.fetch_add(1, std::memory_order_release);
    return {};
  }

  return std::unexpected(Error::TYPE_MISMATCH);
}

std::expected<void, Error> Dispatcher::retype(
    CNode* root,
    std::uint64_t untyped_cptr,
    std::uint64_t dest_cptr,
    std::uint8_t requested_size_log2,
    std::uint64_t offset
) noexcept {
  auto src_slot_res = resolve_cspace_slot(root, untyped_cptr);
  if (!src_slot_res) [[unlikely]]
    return std::unexpected(src_slot_res.error());

  auto dest_slot_res = resolve_cspace_slot(root, dest_cptr);
  if (!dest_slot_res) [[unlikely]]
    return std::unexpected(dest_slot_res.error());

  auto val_res = (*src_slot_res)->validate();
  if (!val_res) [[unlikely]]
    return std::unexpected(val_res.error());

  auto split_cap = val_res->spawn_untyped(requested_size_log2, offset);
  if (!split_cap) [[unlikely]]
    return std::unexpected(split_cap.error());

  memory::PhysAddr p_addr{val_res->pointer()};
  auto p_node = p_addr.to_virt().as<ParentGenerationNode>();

  p_node->active_child_count.fetch_add(1, std::memory_order_acquire);

  auto insert_res = (*dest_slot_res)->insert(*split_cap, p_node);
  if (!insert_res) {
    p_node->active_child_count.fetch_sub(1, std::memory_order_release);
    return insert_res;
  }

  return {};
}
}  // namespace kernel::core::capabilities