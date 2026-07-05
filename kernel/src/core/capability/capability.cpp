#include "core/capability/capability.hpp"

#include <cstdint>
#include <expected>

#include "compiler.h"
#include "core/capability/common.hpp"

namespace kernel::core::capabilities {
std::expected<Capability, Error>
Capability::mint(CapRights new_rights, std::uint32_t new_badge) const noexcept {
  const CapRights curr_rights = rights();

  if (!has_rights(curr_rights, new_rights) ||
      !has_rights(curr_rights, CapRights::MINT))
    return std::unexpected(Error::INSUFFICIENT_RIGHTS);

  std::uint32_t final_payload = badge();

  if (new_badge != 0) {
    if (!has_rights(curr_rights, CapRights::BADGE)) [[unlikely]]
      return std::unexpected(Error::INSUFFICIENT_RIGHTS);

    if (type() != Type::ENDPOINT && type() != Type::REPLY)
      return std::unexpected(Error::CANNOT_BE_BADGED);

    final_payload = new_badge;
  }

  return Capability(
      type(),
      new_rights,
      generation(),
      depth(),
      final_payload,
      pointer()
  );
}

std::expected<Capability, Error> Capability::spawn_untyped(
    std::uint8_t new_size_log2,
    std::uint64_t physical_offset
) const noexcept {
  if (type() != Type::UNTYPED) return std::unexpected(Error::TYPE_MISMATCH);
  if (!has_rights(rights(), CapRights::SPLIT))
    return std::unexpected(Error::INSUFFICIENT_RIGHTS);

  if (new_size_log2 > size_log2()) return std::unexpected(Error::SIZE_MISMATCH);

  std::uint64_t max_offset = (1ul << size_log2()) - (1ul << new_size_log2);
  if (physical_offset > max_offset)
    return std::unexpected(Error::SIZE_MISMATCH);

  return Capability(
      Type::UNTYPED,
      rights(),
      generation(),
      depth(),
      new_size_log2,
      pointer() + physical_offset
  );
}
}  // namespace kernel::core::capabilities