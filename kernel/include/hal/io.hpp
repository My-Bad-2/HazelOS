#ifndef KERNEL_HAL_IO_HPP
#define KERNEL_HAL_IO_HPP 1

#include <atomic>
#include <concepts>
#include <cstdint>

namespace kernel {
namespace hal {
namespace io {
template <typename T>
concept MmioType =
    std::same_as<T, std::uint8_t> || std::same_as<T, std::uint16_t> ||
    std::same_as<T, std::uint32_t> ||
    (std::same_as<T, std::uint64_t> && sizeof(void*) == 8);

template <typename T>
  requires(sizeof(T) <= sizeof(std::uint64_t))
inline void mmio_write(volatile T* addr, T val) {
  // Ensure previous memory writes are globally visible
  std::atomic_thread_fence(std::memory_order_release);
  *addr = val;

  // Prevent subsequent reads/writes from floating above this write
  std::atomic_thread_fence(std::memory_order_seq_cst);
}

template <typename T>
  requires(sizeof(T) <= sizeof(std::uint64_t))
inline T mmio_read(volatile T* addr) {
  // Ensure previous operations complete before reading the hardware state
  std::atomic_thread_fence(std::memory_order_seq_cst);
  T val = *addr;

  // Ensure subsequent operations do not rely on stale speculative reads
  std::atomic_thread_fence(std::memory_order_acquire);
  return val;
}
}  // namespace io
}  // namespace hal
}  // namespace kernel

#endif