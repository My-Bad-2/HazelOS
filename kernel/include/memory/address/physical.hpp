#ifndef KERNEL_MEMORY_ADDRESS_PHYSICAL_HPP
#define KERNEL_MEMORY_ADDRESS_PHYSICAL_HPP 1

#include <compare>
#include <cstdint>
#include <type_traits>

#include "compiler.h"
#include "memory/memory.hpp"

namespace kernel {
namespace memory {
class VirtAddr;

class PhysAddr {
 private:
  std::uintptr_t m_addr;

 public:
  constexpr PhysAddr() noexcept : m_addr(0) {}
  constexpr explicit PhysAddr(std::uintptr_t addr) noexcept : m_addr(addr) {}

  __nodiscard constexpr std::uintptr_t raw() const noexcept {
    return m_addr;
  }

  __nodiscard constexpr bool is_null() const noexcept {
    return m_addr == 0;
  }

  constexpr explicit operator bool() const noexcept {
    return m_addr != 0;
  }

  template <std::size_t Alignment = PAGE_SIZE_SMALL>
  __nodiscard constexpr bool is_aligned() const noexcept {
    return libs::maths::is_aligned(m_addr, Alignment);
  }

  template <std::size_t Alignment = PAGE_SIZE_SMALL>
  __nodiscard constexpr PhysAddr align_up() const noexcept {
    return PhysAddr{libs::maths::align_up(m_addr, Alignment)};
  }

  template <std::size_t Alignment = PAGE_SIZE_SMALL>
  __nodiscard constexpr PhysAddr align_down() const noexcept {
    return PhysAddr{libs::maths::align_down(m_addr, Alignment)};
  }

  __nodiscard constexpr PhysAddr offset(std::size_t bytes) const noexcept {
    return PhysAddr{m_addr + bytes};
  }

  __nodiscard constexpr VirtAddr to_virt() const noexcept;

  constexpr PhysAddr operator+(std::size_t offset) const noexcept {
    return PhysAddr{m_addr + offset};
  }

  constexpr PhysAddr& operator+=(std::size_t offset) noexcept {
    m_addr += offset;
    return *this;
  }

  constexpr PhysAddr operator-(std::size_t offset) const noexcept {
    return PhysAddr{m_addr - offset};
  }

  constexpr PhysAddr& operator-=(std::size_t offset) noexcept {
    m_addr -= offset;
    return *this;
  }

  constexpr std::uintptr_t operator-(PhysAddr other) const noexcept {
    return m_addr - other.m_addr;
  }

  constexpr auto operator<=>(const PhysAddr&) const noexcept = default;
};

static_assert(
    sizeof(PhysAddr) == sizeof(std::uintptr_t),
    "PhysAddr must be exactly 8 bytes"
);
static_assert(
    std::is_trivially_copyable_v<PhysAddr>,
    "PhysAddr must be a trivially copyable"
);
static_assert(
    std::is_standard_layout_v<PhysAddr>,
    "PhysAddr must have standard layout"
);
}  // namespace memory
}  // namespace kernel

#endif  // KERNEL_MEMORY_ADDRESS_PHYSICAL_HPP