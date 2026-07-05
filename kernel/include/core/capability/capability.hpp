#ifndef KERNEL_INCLUDE_CORE_CAPABILITY_HPP
#define KERNEL_INCLUDE_CORE_CAPABILITY_HPP 1

#include <cstdint>
#include <expected>

#include "compiler.h"
#include "core/capability/common.hpp"

namespace kernel::core::capabilities {
class alignas(16) Capability {
 public:
  enum class Type : std::uint8_t {
    NONE = 0,
    UNTYPED,
    CNODE,
    ENDPOINT,
    REPLY,
    FRAME,
    PAGE_TABLE,
    THREAD,
    PROCESS
  };

 private:
  // [ Type: 8b | Rights: 16b | Generation: 16b | Depth: 4b | Badge/Size: 28b |
  // Pointer: 56b]
  uint128_t m_raw{0};

  static constexpr uint128_t TYPE_SHIFT    = 120;
  static constexpr uint128_t RIGHTS_SHIFT  = 104;
  static constexpr uint128_t GEN_SHIFT     = 88;
  static constexpr uint128_t DEPTH_SHIFT   = 84;
  static constexpr uint128_t PAYLOAD_SHIFT = 56;

  static constexpr uint128_t PTR_MASK     = 0x00ffffffffffffff;
  static constexpr uint128_t PAYLOAD_MASK = 0x0fffffff;

 public:
  constexpr Capability() noexcept = default;
  constexpr Capability(uint128_t raw) noexcept : m_raw(raw) {}

  constexpr Capability(
      Type type,
      CapRights rights,
      std::uint16_t generation,
      std::uint8_t depth,
      std::uint32_t payload,
      std::uint64_t pointer
  ) noexcept {
    m_raw = (static_cast<uint128_t>(type) << TYPE_SHIFT) |
            (static_cast<uint128_t>(rights) << RIGHTS_SHIFT) |
            (static_cast<uint128_t>(generation) << GEN_SHIFT) |
            (static_cast<uint128_t>(depth & 0xF) << DEPTH_SHIFT) |
            (static_cast<uint128_t>(payload & PAYLOAD_MASK) << PAYLOAD_SHIFT) |
            (static_cast<uint128_t>(pointer) & PTR_MASK);
  }

  __nodiscard constexpr Type type() const noexcept {
    return static_cast<Type>(m_raw >> TYPE_SHIFT);
  }

  __nodiscard constexpr CapRights rights() const noexcept {
    return static_cast<CapRights>((m_raw >> RIGHTS_SHIFT) & 0xffff);
  }

  __nodiscard constexpr std::uint16_t generation() const noexcept {
    return static_cast<std::uint16_t>((m_raw >> GEN_SHIFT) & 0xffff);
  }

  __nodiscard constexpr std::uint8_t depth() const noexcept {
    return static_cast<std::uint8_t>((m_raw >> DEPTH_SHIFT) & 0xf);
  }

  __nodiscard constexpr std::uint64_t pointer() const noexcept {
    return static_cast<std::uint64_t>(m_raw & PTR_MASK);
  }

  __nodiscard constexpr bool is_null() const noexcept {
    return m_raw == 0;
  }

  __nodiscard constexpr uint128_t raw() const noexcept {
    return m_raw;
  }

  __nodiscard constexpr std::uint32_t badge() const noexcept {
    return static_cast<std::uint32_t>((m_raw >> PAYLOAD_SHIFT) & 0xffffffff);
  }

  __nodiscard constexpr std::uint8_t size_log2() const noexcept {
    return static_cast<std::uint8_t>((m_raw >> PAYLOAD_SHIFT) & 0xff);
  }

  __nodiscard std::expected<Capability, Error>
  mint(CapRights new_rights, std::uint32_t new_badge = 0) const noexcept;

  __nodiscard std::expected<Capability, Error> spawn_untyped(
      std::uint8_t new_size_log2,
      std::uint64_t physical_offset
  ) const noexcept;
};
}  // namespace kernel::core::capabilities

#endif