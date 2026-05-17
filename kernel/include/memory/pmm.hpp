#ifndef KERNEL_MEMORY_PMM_HPP
#define KERNEL_MEMORY_PMM_HPP 1

#include <atomic>
#include <cstddef>
#include <cstdint>

#include "memory/address/physical.hpp"
#include "memory/address/virtual.hpp"

namespace kernel {
namespace memory {
class PhysicalManager {
 private:
  static inline limine_memmap_response* s_mmap = nullptr;

  static inline std::atomic<std::size_t> s_current_region_idx{0};
  static inline std::atomic<std::uintptr_t> s_current_bump_ptr{0};

 public:
  static void initialize(limine_memmap_response* mmap) noexcept;

  __nodiscard static PhysAddr alloc_pages(std::size_t count) noexcept;
  __nodiscard static PhysAddr alloc_zeroed_pages(std::size_t count) noexcept;
  static void finalize_for_handoff() noexcept;
};
}  // namespace memory
}  // namespace kernel

#endif  // KERNEL_MEMORY_PMM_HPP