#ifndef KERNEL_INCLUDE_CORE_CAPABILITIES_HPP
#define KERNEL_INCLUDE_CORE_CAPABILITIES_HPP 1

#include <cstdint>

#include "core/capability/capability.hpp"
#include "core/capability/cnode.hpp"
#include "core/capability/common.hpp"
#include "core/capability/cslot.hpp"
#include "core/capability/resolver.hpp"

namespace kernel::core::capabilities {
class Dispatcher {
 public:
  static std::expected<void, Error>
  copy(CNode* root, std::uint64_t src_cptr, std::uint64_t dest_cptr) noexcept;

  static std::expected<void, Error>
  move(CNode* root, std::uint64_t src_cptr, std::uint64_t dest_cptr) noexcept;

  static std::expected<void, Error> mint(
      CNode* root,
      std::uint64_t src_cptr,
      std::uint64_t dest_cptr,
      CapRights new_rights,
      std::uint32_t new_badge
  ) noexcept;

  static std::expected<void, Error>
  erase(CNode* root, std::uint64_t target_cptr) noexcept;

  static std::expected<void, Error>
  revoke(CNode* root, std::uint64_t target_cptr) noexcept;

  static std::expected<void, Error> retype(
      CNode* root,
      std::uint64_t untyped_cptr,
      std::uint64_t dest_cptr,
      std::uint8_t requested_size_log2,
      std::uint64_t offset
  ) noexcept;
};
}  // namespace kernel::core::capabilities

#endif