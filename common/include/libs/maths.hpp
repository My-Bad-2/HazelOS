#ifndef COMMON_LIBS_MATHS_HPP
#define COMMON_LIBS_MATHS_HPP 1

#include <assert.h>
#include <bit>
#include <climits>
#include <concepts>
#include <cstdint>

#include "compiler.h"

namespace libs {
namespace maths {
/**
 * @brief Aligns `n` down to the nearest multiple of `a`,
 * @param a Must be a power of 2.
 */
template <std::unsigned_integral T, std::unsigned_integral U>
__nodiscard inline constexpr T align_down(T n, U a) noexcept {
  assert(std::has_single_bit(a) && "Alignment must be a power of two");
  __assume(std::has_single_bit(a));

  return n & ~static_cast<T>(a - 1);
}

/**
 * @brief Aligns `n` up to the nearest multiple of `a`.
 * @param a Must be a power of 2.
 */
template <std::unsigned_integral T, std::unsigned_integral U>
__nodiscard inline constexpr T align_up(T n, U a) noexcept {
  assert(std::has_single_bit(a) && "Alignment must be a power of two");
  __assume(std::has_single_bit(a));

  return (n + static_cast<T>(a) - 1) & ~static_cast<T>(a - 1);
}

/**
 * @brief Divides `n` by `a`, rounding up.
 * @note `a` does not need to a power of 2
 */
template <std::unsigned_integral T, std::unsigned_integral U>
__nodiscard inline constexpr T div_roundup(T n, U a) noexcept {
  assert(a != 0 && "Division by zero");

  return (n + static_cast<T>(a) - 1) / static_cast<T>(a);
}

/**
 * @brief Divides `n` by `a`, rounding down.
 */
template <std::unsigned_integral T, std::unsigned_integral U>
__nodiscard inline constexpr T div_rounddown(T n, U a) noexcept {
  assert(a != 0 && "Division by zero");

  return n / static_cast<T>(a);
}

/**
 * @brief Aligns a pointer up to the nearest multiple of `a`.
 */
template <typename T, std::unsigned_integral U>
__nodiscard inline T* align_up_ptr(T* ptr, U a) noexcept {
  auto addr = reinterpret_cast<std::uintptr_t>(ptr);
  return reinterpret_cast<T*>(align_up(addr, a));
}

/**
 * @brief Aligns a pointer down to the nearest multiple of `a`.
 */
template <typename T, std::unsigned_integral U>
__nodiscard inline T* align_down_ptr(T* ptr, U a) noexcept {
  auto addr = reinterpret_cast<std::uintptr_t>(ptr);
  return reinterpret_cast<T*>(align_down(addr, a));
}

/**
 * @brief Checks if a number (or address) is aligned to 'a'.
 * @param a Must be a power of 2.
 */
template <std::unsigned_integral T, std::unsigned_integral U>
__nodiscard inline constexpr bool is_aligned(T n, U a) noexcept {
  assert(std::has_single_bit(a) && "Alignment must be a power of two");
  __assume(std::has_single_bit(a));

  return (n & static_cast<T>(a - 1)) == 0;
}

/**
 * @brief Pointer overload for alignment checking.
 */
template <typename T, std::unsigned_integral U>
__nodiscard inline bool is_aligned_ptr(const T* ptr, U a) noexcept {
  return is_aligned(reinterpret_cast<std::uintptr_t>(ptr), a);
}

/**
 * @brief Generates a contiguous bitmask of `N` ones starting from the 0th bit.
 * @example bit_mask<std::uint32_t>(4) => 0b1111 (15);
 */
template <std::unsigned_integral T>
__nodiscard inline constexpr T bit_mask(std::size_t bits) noexcept {
  // Shifting by the width of the type is UB
  if (bits >= sizeof(T) * CHAR_BIT) return ~T{0};
  return (T{1} << bits) - 1;
}

/**
 * @brief Checks if a integral value has specific bit indices set to 1.
 * @example has_bits(flags, 0, 3, 5) returns true if bits 0, 3, and 5 are all 1.
 */
template <std::unsigned_integral T, std::integral... U>
__nodiscard inline constexpr bool has_bits(T val, U... bit_indices) noexcept {
  // The fold expression (&& ...) directly expands the binary operator to all
  // elements in `bit_indices`.
  return (((val & (T{1} << bit_indices)) != 0) && ...);
}

/**
 * @brief Checks if atlease one of the specified bit indices is set to 1.
 */
template <std::unsigned_integral T, std::integral... U>
__nodiscard inline constexpr bool
has_any_bit(T val, U... bit_indices) noexcept {
  return (((val & (T{1} << bit_indices)) != 0) || ...);
}

template <std::unsigned_integral T>
__nodiscard inline constexpr T kib(T num) noexcept {
  return num << 10;
}

template <std::unsigned_integral T>
__nodiscard inline constexpr T mib(T num) noexcept {
  return num << 20;
}

template <std::unsigned_integral T>
__nodiscard inline constexpr T gib(T num) noexcept {
  return num << 30;
}

namespace literals {
__nodiscard consteval unsigned long operator ""_KiB(
    unsigned long long num
) {
  return num << 10;
}

__nodiscard consteval unsigned long operator ""_MiB(
    unsigned long long num
) {
  return num << 20;
}

__nodiscard consteval unsigned long operator ""_GiB(
    unsigned long long num
) {
  return num << 30;
}

__nodiscard consteval unsigned long operator ""_KiB(long double num) {
  return static_cast<unsigned long>(num * 1024);
}

__nodiscard consteval unsigned long operator ""_MiB(long double num) {
  return static_cast<unsigned long>(num * 1024 * 1024);
}

__nodiscard consteval unsigned long operator ""_GiB(long double num) {
  return static_cast<unsigned long>(num * 1024 * 1024 * 1024);
}
}  // namespace literals

/**
 * @brief Returns the base-2 logarithm of a value.
 */
template <std::unsigned_integral T>
__nodiscard inline constexpr T log2(T val) noexcept {
  assert(val > 0 && "log2(0) is undefined.");
  return std::bit_width(val) - 1;
}

/**
 * @brief Returns 2 raised to the power of 'exponent'.
 */
template <std::unsigned_integral T = std::size_t>
__nodiscard inline constexpr T pow2(std::size_t exponent) noexcept {
  assert(
      exponent < sizeof(T) * CHAR_BIT && "Shift exponent exceeds type width!"
  );
  return T{1} << exponent;
}

/**
 * @brief Checks if a number is a power of 2.
 */
template <std::unsigned_integral T>
__nodiscard inline constexpr bool is_pow2(T num) noexcept {
  return std::has_single_bit(num);
}

/**
 * @brief Rounds up to the next power of 2.
 */
template <std::unsigned_integral T>
__nodiscard inline constexpr T next_pow2(T val) noexcept {
  return std::bit_ceil(val);
}

/**
 * @brief Rounds down to the previous power of 2.
 */
template <std::unsigned_integral T>
__nodiscard inline constexpr T pre_pow2(T val) noexcept {
  return std::bit_floor(val);
}
}  // namespace maths
}  // namespace libs

#endif