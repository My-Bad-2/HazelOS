#include "memory/pmm.hpp"

#include <atomic>
#include <cstdint>
#include <string.h>

#include "external/limine.h"
#include "memory/address/physical.hpp"
#include "memory/address/virtual.hpp"
#include "memory/memory.hpp"

namespace kernel {
namespace memory {
void PhysicalManager::initialize(limine_memmap_response* mmap) noexcept {
  s_mmap = mmap;
}

PhysAddr PhysicalManager::alloc_pages(std::size_t count) noexcept {
  const std::size_t alloc_size = count * PAGE_SIZE_SMALL;

  while (true) {
    std::size_t idx = s_current_region_idx.load(std::memory_order_acquire);

    if (idx >= s_mmap->entry_count) return PhysAddr{0};

    const limine_memmap_entry* entry = s_mmap->entries[idx];

    if (entry->type != LIMINE_MEMMAP_USABLE) {
      // If unusable, try to advance the index.
      s_current_region_idx.compare_exchange_strong(
          idx,
          idx + 1,
          std::memory_order_release,
          std::memory_order_relaxed
      );
      continue;
    }

    std::uint64_t old_ptr = s_current_bump_ptr.load(std::memory_order_acquire);

    // Sync the bump pointer if we've just entered a new region
    if (old_ptr < entry->base) {
      s_current_bump_ptr.compare_exchange_strong(
          old_ptr,
          entry->base,
          std::memory_order_release,
          std::memory_order_relaxed
      );
      continue;
    }

    const std::uintptr_t aligned_ptr =
        libs::maths::align_up(old_ptr, PAGE_SIZE_SMALL);
    const std::uint64_t new_ptr = aligned_ptr + alloc_size;

    // Check if allocation fits within the current region
    if (new_ptr <= entry->base + entry->length) {
      if (s_current_bump_ptr.compare_exchange_weak(
              old_ptr,
              new_ptr,
              std::memory_order_release,
              std::memory_order_relaxed
          )) {
        return PhysAddr{aligned_ptr};
      }
    } else {
      s_current_region_idx.compare_exchange_strong(
          idx,
          idx + 1,
          std::memory_order_release,
          std::memory_order_relaxed
      );
    }
  }
}

PhysAddr PhysicalManager::alloc_zeroed_pages(std::size_t count) noexcept {
  PhysAddr phys = alloc_pages(count);
  if (!phys.is_null()) {
    const VirtAddr virt = phys.to_virt();
    memset(virt.as<void>(), 0, count * PAGE_SIZE_SMALL);
  }

  return phys;
}

void PhysicalManager::finalize_for_handoff() noexcept {
  const std::size_t final_idx =
      s_current_region_idx.load(std::memory_order_acquire);
  const std::size_t final_ptr =
      s_current_bump_ptr.load(std::memory_order_acquire);

  // Mark all completely exhausted regions as reserved so the userspace PMM
  // ignores them
  for (std::size_t i = 0; i < final_idx; ++i)
    if (s_mmap->entries[i]->type == LIMINE_MEMMAP_USABLE)
      s_mmap->entries[i]->type = MEMMAP_BOOT_ALLOCATED;

  // Shrink the current active region to where the bump pointer stopped
  if (final_idx < s_mmap->entry_count &&
      s_mmap->entries[final_idx]->type == LIMINE_MEMMAP_USABLE) {
    limine_memmap_entry* entry = s_mmap->entries[final_idx];
    const std::size_t consumed = final_ptr - entry->base;

    entry->base = final_ptr;
    entry->length -= consumed;
  }
}
}  // namespace memory
}  // namespace kernel