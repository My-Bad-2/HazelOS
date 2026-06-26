
#ifndef KERNEL_MEMORY_VMM_HPP
#define KERNEL_MEMORY_VMM_HPP 1

#include <cstdint>

#include "compiler.h"
#include "memory/address_space.hpp"
#include "memory/vm/PageTableAllocator.hpp"
#include "memory/vm/flags.hpp"

namespace kernel {
namespace memory {
struct KernelSegment {
 private:
  const void* m_start;
  const void* m_end;
  VmFlags m_flags;

 public:
  constexpr KernelSegment() noexcept = default;
  constexpr KernelSegment(
      const void* start,
      const void* end,
      VmFlags flags = VmFlags::Read | VmFlags::Write
  )
      : m_start(start), m_end(end), m_flags(flags) {}

  __nodiscard std::size_t size_bytes() const noexcept {
    return reinterpret_cast<std::uintptr_t>(m_end) -
           reinterpret_cast<std::uintptr_t>(m_start);
  }

  __nodiscard const void* start() const noexcept {
    return m_start;
  }

  __nodiscard const void* end() const noexcept {
    return m_end;
  }

  __nodiscard VmFlags flags() const noexcept {
    return m_flags;
  }
};

class VirtualManager {
 public:
  static void initialize(limine_memmap_response* response) noexcept;

  static bool map_mmio(VirtAddr virt, PhysAddr phys) noexcept;

 private:
  static void map_hhdm(
      AddressSpace& space,
      IPageTableAllocator& alloc,
      limine_memmap_response* response
  ) noexcept;
  static void
  map_kernel(AddressSpace& space, IPageTableAllocator& alloc) noexcept;
};
}  // namespace memory
}  // namespace kernel

#endif