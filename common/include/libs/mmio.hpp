#ifndef COMMON_LIBS_HPP
#define COMMON_LIBS_HPP 1

#include <atomic>
#include <concepts>
#include <cstddef>
#include <cstdint>

#include "compiler.h"

namespace libs {
namespace mmio {
template <typename T>
concept ValidMmioWidth =
    std::same_as<T, std::uint8_t> || std::same_as<T, std::uint16_t> ||
    std::same_as<T, std::uint32_t> || std::same_as<T, std::uint64_t>;

template <typename T>
concept IsMmio = requires(T t) {
  // The struct must declare underlying size (`using value_type =
  // std::uint32_t`)
  typename T::value_type;
  requires ValidMmioWidth<typename T::value_type>;
};

template <typename T>
concept HasOffset = requires {
  { T::OFFSET } -> std::convertible_to<std::size_t>;
};

template <IsMmio Reg>
__nodiscard inline Reg read(const volatile void* base_addr) noexcept {
  using width_t = typename Reg::value_type;

  auto* byte_addr = static_cast<const volatile std::byte*>(base_addr);
  if constexpr (HasOffset<Reg>) byte_addr += Reg::OFFSET;

  auto target_addr = reinterpret_cast<const volatile width_t*>(byte_addr);

  std::atomic_thread_fence(std::memory_order_seq_cst);
  width_t val = *target_addr;
  std::atomic_thread_fence(std::memory_order_acquire);

  return Reg{val};
}

template <IsMmio Reg>
inline void write(volatile void* base_addr, Reg val) noexcept {
  using width_t = typename Reg::value_type;

  auto* byte_addr = static_cast<volatile std::byte*>(base_addr);
  if constexpr (HasOffset<Reg>) byte_addr += Reg::OFFSET;

  auto target_addr = reinterpret_cast<volatile width_t*>(byte_addr);

  std::atomic_thread_fence(std::memory_order_release);
  *target_addr = val.raw;
  std::atomic_thread_fence(std::memory_order_seq_cst);
}
}  // namespace mmio
}  // namespace libs

#endif