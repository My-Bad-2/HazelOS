#ifndef KERNEL_INCLUDE_CORE_CAPABILITY_CAPABILITY_HPP
#define KERNEL_INCLUDE_CORE_CAPABILITY_CAPABILITY_HPP 1

#include <cstdint>

namespace kernel::core::capabilities {
enum class Error : std::uint8_t {
  SUCCESS = 0,
  INVALID_CAPABILITIY,
  GENERATION_MISMATCH,
  PARENT_REVOKED,
  SLOT_OCCUPIED,
  SLOT_EMPTY,
  INSUFFICIENT_RIGHTS,
  TYPE_MISMATCH,
  MEMORY_ALIGNMENT_FAULT,
  DEPTH_OVERFLOW,
  QUOTA_EXCEEDED,
  INVALID_STATE,
  CANNOT_BE_BADGED,
  SIZE_MISMATCH,
};

enum class CapRights : std::uint16_t {
  NONE        = 0,
  READ        = (1 << 0),   // Read from Object
  WRITE       = (1 << 1),   // Write to object
  EXECUTE     = (1 << 2),   // Execute rights
  GRANT       = (1 << 3),   // Transfer capabilities
  GRANT_REPLY = (1 << 4),   // Transfer one-time reply cap
  SYNC        = (1 << 5),   // Block/Wake on Endpoints
  MINT        = (1 << 6),   // Allow deriving child caps with lesser rights
  REVOKE      = (1 << 7),   // Allow triggering lazy revocation of children
  BADGE       = (1 << 8),   // Allow minting a Badged version
  IDENTIFY    = (1 << 9),   // Allow reading object metadata without rights
  SPLIT       = (1 << 10),  // Allow carving Untypes memory

  ALL        = 0xffff,
  READ_WRITE = READ | WRITE,
  IPC        = SYNC | GRANT | READ | WRITE,
};

constexpr CapRights operator|(CapRights a, CapRights b) noexcept {
  return static_cast<CapRights>(
      static_cast<std::uint16_t>(a) | static_cast<std::uint8_t>(b)
  );
}

constexpr CapRights operator&(CapRights a, CapRights b) noexcept {
  return static_cast<CapRights>(
      static_cast<std::uint8_t>(a) & static_cast<std::uint8_t>(b)
  );
}

constexpr bool has_rights(CapRights current, CapRights required) noexcept {
  return (current & required) == required;
}
}  // namespace kernel::core::capabilities

#endif