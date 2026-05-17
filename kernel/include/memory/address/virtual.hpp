#ifndef KERNEL_MEMORY_ADDRESS_VIRTUAL_HPP
#define KERNEL_MEMORY_ADDRESS_VIRTUAL_HPP 1

#include <compare>
#include <cstdint>
#include <type_traits>

#include "compiler.h"
#include "memory/memory.hpp"

namespace kernel {
namespace memory {
class PhysAddr;

class VirtAddr {
 private:
  std::uintptr_t m_addr;

 public:
  constexpr VirtAddr() noexcept : m_addr(0) {}
  constexpr explicit VirtAddr(std::uint64_t addr) noexcept : m_addr(addr) {}

  template <typename T>
  explicit VirtAddr(T* ptr) noexcept
      : m_addr(reinterpret_cast<std::uintptr_t>(ptr)) {}

  template <typename T = void>
  __nodiscard T* as() const noexcept {
    return reinterpret_cast<T*>(m_addr);
  }

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
  __nodiscard constexpr VirtAddr align_up() const noexcept {
    return VirtAddr{libs::maths::align_up(m_addr, Alignment)};
  }

  template <std::size_t Alignment = PAGE_SIZE_SMALL>
  __nodiscard constexpr VirtAddr align_down() const noexcept {
    return VirtAddr{libs::maths::align_down(m_addr, Alignment)};
  }

  __nodiscard PhysAddr to_phys() const noexcept;

  __nodiscard constexpr VirtAddr offset(std::size_t bytes) const noexcept {
    return VirtAddr{m_addr + bytes};
  }

  constexpr VirtAddr operator+(std::size_t offset) const noexcept {
    return VirtAddr{m_addr + offset};
  }

  constexpr VirtAddr& operator+=(std::size_t offset) noexcept {
    m_addr += offset;
    return *this;
  }

  constexpr VirtAddr operator-(std::size_t offset) const noexcept {
    return VirtAddr{m_addr - offset};
  }

  constexpr VirtAddr& operator-=(std::size_t offset) noexcept {
    m_addr -= offset;
    return *this;
  }

  constexpr std::uintptr_t operator-(VirtAddr other) const noexcept {
    return m_addr - other.m_addr;
  }

  constexpr auto operator<=>(const VirtAddr&) const noexcept = default;
};

static_assert(
    sizeof(VirtAddr) == sizeof(std::uintptr_t),
    "VirtAddr must be exactly 8 bytes"
);
static_assert(
    std::is_trivially_copyable_v<VirtAddr>,
    "VirtAddr must be trivially copyable"
);
static_assert(
    std::is_standard_layout_v<VirtAddr>,
    "VirtAddr must have standard layout"
);
}  // namespace memory
}  // namespace kernel

#endif