#ifndef KERNEL_MEMORY_HPP
#define KERNEL_MEMORY_HPP 1

#include <concepts>
#include <cstdint>
#include <type_traits>

#include "compiler.h"
#include "core/boot.hpp"
#include "libs/maths.hpp"

namespace kernel {
namespace memory {
namespace details {
/**
 * @brief Deduces a safe and clean return type for higher-half translations.
 * Keeps pointers as pointers, and guarantees integrals map to pointer-sized
 * types.
 */
template <typename T>
using GetReturnType = std::conditional_t<
    std::is_pointer_v<T>,
    T,
    std::conditional_t<std::is_signed_v<T>, std::intptr_t, std::uintptr_t>>;

/**
 * @brief Helper to cast any pointer or integer to raw uintptr_t.
 */
template <typename T>
__nodiscard inline std::uintptr_t to_uintptr(T val) noexcept {
  if constexpr (std::is_pointer_v<T>)
    return reinterpret_cast<std::uintptr_t>(val);
  return static_cast<std::uintptr_t>(val);
}

template <typename U>
__nodiscard inline U from_uintptr(std::uintptr_t addr) noexcept {
  if constexpr (std::is_pointer_v<U>) return reinterpret_cast<U>(addr);
  return static_cast<U>(addr);
}

using namespace libs::maths::literals;
constexpr std::size_t __page_size_4kb = 4_KiB;
constexpr std::size_t __page_size_2mb = 2_MiB;
constexpr std::size_t __page_size_1gb = 1_GiB;
}  // namespace details

constexpr std::size_t PAGE_SIZE_SMALL = details::__page_size_4kb;
constexpr std::size_t PAGE_SIZE_LARGE = details::__page_size_2mb;
constexpr std::size_t PAGE_SIZE_HUGE  = details::__page_size_1gb;

/**
 * @brief Checks whether a value or pointer lives in the higher-half memory
 * space.
 */
__nodiscard inline bool is_higher_half(auto val) noexcept {
  return details::to_uintptr(val) >= boot::get_hhdm_offset();
}

/**
 * @brief Translates a physical address into a higher-half virtual address.
 */
template <typename T, typename U = details::GetReturnType<T>>
__nodiscard inline U to_higher_half(T val) noexcept {
  const std::uintptr_t addr = details::to_uintptr(val);

  if (is_higher_half(addr)) return details::to_uintptr<U>(addr);
  return details::from_uintptr<U>(addr + boot::get_hhdm_offset());
}

/**
 * @brief Translates a higher-half virtual address back down to its physical
 * mapping.
 */
template <typename Type, typename U = details::GetReturnType<Type>>
__nodiscard inline U from_higher_half(Type val) noexcept {
  const std::uintptr_t raw_addr = details::to_uintptr(val);

  if (!is_higher_half(raw_addr)) return details::from_uintptr<U>(raw_addr);
  return details::from_uintptr<U>(raw_addr - boot::get_hhdm_offset());
}
}  // namespace memory
}  // namespace kernel

#endif  // KERNEL_MEMORY_HPP