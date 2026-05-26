#ifndef KERNEL_MEMORY_ADDRESS_SPACE_HPP
#define KERNEL_MEMORY_ADDRESS_SPACE_HPP 1

#include <atomic>
#include <cstdint>

#include "memory/address/physical.hpp"
#include "memory/address/virtual.hpp"
#include "memory/vm/PageTableAllocator.hpp"
#include "memory/vm/asid.hpp"
#include "memory/vm/flags.hpp"
#include "memory/vm/table.hpp"

namespace kernel {
namespace memory {
constexpr std::size_t MASK_WORDS = (MAX_CPU_COUNT + 63) / 64;
enum class PageSize : std::uint8_t { Size4KB = 1, Size2MB = 2, Size1GB = 3 };

class AddressSpace {
 private:
  PhysAddr m_root_phys;
  std::uint8_t m_max_level;

  std::array<std::atomic<std::uint64_t>, MASK_WORDS> m_active_cpus{};
  std::array<CacheEntry, MAX_CPU_COUNT> m_pcid_cache{};

  __nodiscard PageTable* walk_to_table(
      VirtAddr virt,
      std::uint8_t target_level,
      IPageTableAllocator* alloc
  ) noexcept;

  void destroy_table(
      PhysAddr table_phys,
      std::uint8_t curr_level,
      bool is_root,
      IPageTableAllocator& alloc
  ) noexcept;

  bool clone_table_recursive(
      PhysAddr src_phys,
      PhysAddr dest_phys,
      std::uint8_t level,
      bool is_root,
      IPageTableAllocator& alloc,
      arch::PageFlags clear_mask,
      arch::PageFlags set_mask
  ) const noexcept;

 public:
  explicit AddressSpace(PhysAddr root_phys, bool uses_pml5 = false) noexcept;

  __nodiscard PhysAddr get_root() const noexcept {
    return m_root_phys;
  }

  void mark_active(std::uint32_t core_id) noexcept {
    if (core_id >= MAX_CPU_COUNT) return;

    const std::uint64_t bit = 1ul << (core_id % 64);
    m_active_cpus[core_id / 64].fetch_or(bit, std::memory_order_relaxed);
  }

  void mark_inactive(std::uint32_t core_id) noexcept {
    if (core_id >= MAX_CPU_COUNT) return;

    const std::uint64_t bit = 1ul << (core_id % 64);
    m_active_cpus[core_id / 64].fetch_and(~bit, std::memory_order_relaxed);
  }

  void load() noexcept;

  bool remap_range(
      VirtAddr start_virt,
      PhysAddr start_phys,
      std::size_t count,
      VmFlags flags,
      CacheMode cache,
      PageSize size,
      std::uint8_t pkey,
      IPageTableAllocator& alloc
  ) noexcept;

  __nodiscard bool map_range(
      VirtAddr start_virt,
      PhysAddr start_phys,
      std::size_t count,
      VmFlags flags,
      CacheMode cache,
      PageSize size,
      std::uint8_t pkey,
      IPageTableAllocator& alloc
  ) noexcept;

  __nodiscard bool
  unmap_range(VirtAddr start_virt, std::size_t count, PageSize size) noexcept;
  __nodiscard PhysAddr resolve(VirtAddr virt) const noexcept;

  void dispatch_tlb_shootdown(VirtAddr virt) noexcept;
  void dispatch_tlb_shootdown_context() noexcept;

  void handle_shootdown_context_ipi() noexcept;
  void handle_shootdown_ipi(VirtAddr virt) noexcept;
  void destroy(IPageTableAllocator& alloc) noexcept;

  void sync_kernel_half(const AddressSpace& kernel_space) noexcept;
  static bool create_userspace(
      AddressSpace* dest,
      const AddressSpace& master_kernel_space,
      IPageTableAllocator& alloc,
      bool uses_pml5
  ) noexcept;

  __nodiscard bool clone_userspace_into(
      AddressSpace* dest,
      IPageTableAllocator& alloc,
      VmFlags clear_mask,
      VmFlags set_mask
  ) const noexcept;
};

extern AddressSpace* kernel_space;
}  // namespace memory
}  // namespace kernel

#endif