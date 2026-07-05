#ifndef KERNEL_INCLUDE_CORE_CAPABILITY_RESOLVER_HPP
#define KERNEL_INCLUDE_CORE_CAPABILITY_RESOLVER_HPP 1

#include <cstdint>

#include "core/capability/capability.hpp"
#include "core/capability/cnode.hpp"
#include "core/capability/common.hpp"
#include "memory/address/physical.hpp"
#include "memory/address/virtual.hpp"

namespace kernel::core::capabilities {
template <typename T>
struct ResolvedObject {
  T* obj;
  std::uint32_t badge;
};

template <typename T>
__nodiscard std::expected<ResolvedObject<T>, Error> resolve_object(
    CNode* root_cnode,
    std::uint64_t cptr,
    Capability::Type expected_type,
    CapRights required_rights
) {
  auto cap_res = resolve_cspace(root_cnode, cptr);
  if (!cap_res) [[unlikely]]
    return std::unexpected(cap_res.error());

  const Capability& cap = *cap_res;

  if (cap.type() != expected_type) [[unlikely]]
    return std::unexpected(Error::TYPE_MISMATCH);

  if (!has_rights(cap.rights(), required_rights)) [[unlikely]]
    return std::unexpected(Error::INSUFFICIENT_RIGHTS);

  T* kernel_obj = memory::PhysAddr{cap.pointer()}.to_virt().as<T>();
  return ResolvedObject<T>{.obj = kernel_obj, .badge = cap.badge()};
}
}  // namespace kernel::core::capabilities

#endif