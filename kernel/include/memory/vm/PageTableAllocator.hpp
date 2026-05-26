#ifndef KERNEL_MEMORY_VM_PAGE_TABLE_ALLOCATOR_HPP
#define KERNEL_MEMORY_VM_PAGE_TABLE_ALLOCATOR_HPP 1

#include "memory/address/physical.hpp"
#include "memory/pmm.hpp"

namespace kernel {
namespace memory {
class IPageTableAllocator {
 public:
  __nodiscard virtual PhysAddr alloc_table_frame() noexcept = 0;
  virtual void free_table_frame(PhysAddr frame) noexcept    = 0;

 protected:
  ~IPageTableAllocator() = default;
};

class BootTableAllocator final : public IPageTableAllocator {
 public:
  __nodiscard PhysAddr alloc_table_frame() noexcept override {
    return PhysicalManager::alloc_zeroed_pages(1);
  }

  void free_table_frame(PhysAddr) noexcept override {}
};
}  // namespace memory
}  // namespace kernel

#endif