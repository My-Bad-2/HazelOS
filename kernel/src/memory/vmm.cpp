#include "memory/vmm.hpp"

#include <cstdint>

#include "core/boot.hpp"
#include "core/logger.hpp"
#include "external/limine.h"
#include "hal/cpu.hpp"
#include "libs/maths.hpp"
#include "memory/address/physical.hpp"
#include "memory/address/virtual.hpp"
#include "memory/address_space.hpp"
#include "memory/memory.hpp"
#include "memory/paging/paging.hpp"
#include "memory/vm/PageTableAllocator.hpp"
#include "memory/vm/flags.hpp"

extern "C" {
extern const std::uint8_t __limine_requests_start[], __limine_requests_end[];
extern const std::uint8_t __text_start[], __text_end[];
extern const std::uint8_t __rodata_start[], __rodata_end[];
extern const std::uint8_t __data_start[], __data_end[];
extern const std::uint8_t __bss_start[], __bss_end[];
}

namespace kernel {
namespace memory {
namespace {
static std::byte kernel_space_buffer[sizeof(AddressSpace)] = {};
log::Logger vmm_logger{"VMM"};

struct KaslrMath {
  __nodiscard static PhysAddr to_phys(const void* symbol) noexcept {
    const std::uintptr_t virt_base =
        boot::kernel_addr_request.response->virtual_base;
    const std::uintptr_t phys_base =
        boot::kernel_addr_request.response->physical_base;

    const std::uintptr_t symbol_vaddr =
        reinterpret_cast<std::uintptr_t>(symbol);

    if (symbol_vaddr < virt_base) return PhysAddr(0);

    const std::uintptr_t offset = symbol_vaddr - virt_base;
    return PhysAddr(phys_base + offset);
  }
};

class RegionMapper {
 private:
  __nodiscard static constexpr PageSize
  get_optimal_page_size(std::uintptr_t paddr, std::size_t remaining) noexcept {
    if (remaining >= PAGE_SIZE_HUGE &&
        libs::maths::is_aligned(paddr, PAGE_SIZE_HUGE))
      return PageSize::Size1GB;

    if (remaining >= PAGE_SIZE_LARGE &&
        libs::maths::is_aligned(paddr, PAGE_SIZE_LARGE))
      return PageSize::Size2MB;

    return PageSize::Size4KB;
  }

 public:
  static bool map(
      AddressSpace& space,
      VirtAddr v_base,
      PhysAddr p_base,
      std::size_t length,
      VmFlags flags,
      CacheMode cache,
      IPageTableAllocator& alloc
  ) noexcept {
    const std::size_t aligned_length =
        libs::maths::align_up(length, PAGE_SIZE_SMALL);
    std::uintptr_t current_phys = p_base.raw();
    std::uintptr_t current_virt = v_base.raw();
    std::size_t remaining       = aligned_length;

    while (remaining > 0) {
      const PageSize size     = get_optimal_page_size(current_phys, remaining);
      std::size_t batch_count = 1;
      std::size_t page_bytes  = PAGE_SIZE_SMALL;

      if (size == PageSize::Size4KB) {
        const std::uintptr_t next_2mb_boundary =
            libs::maths::align_down(current_phys, PAGE_SIZE_LARGE) +
            PAGE_SIZE_LARGE;
        const std::size_t max_bytes =
            std::min(remaining, next_2mb_boundary - current_phys);

        batch_count = max_bytes / PAGE_SIZE_SMALL;
        page_bytes  = PAGE_SIZE_SMALL;
      } else if (size == PageSize::Size2MB) {
        const std::uintptr_t next_1gb_boundary =
            libs::maths::align_down(current_phys, PAGE_SIZE_HUGE) +
            PAGE_SIZE_HUGE;
        const std::size_t max_bytes =
            std::min(remaining, next_1gb_boundary - current_phys);

        batch_count = max_bytes / PAGE_SIZE_LARGE;
        page_bytes  = PAGE_SIZE_LARGE;
      } else {
        batch_count = remaining / PAGE_SIZE_HUGE;
        page_bytes  = PAGE_SIZE_HUGE;
      }

      if (!space.map_range(
              VirtAddr(current_virt),
              PhysAddr(current_phys),
              batch_count,
              flags,
              cache,
              size,
              0,
              alloc
          ))
        return false;

      const std::size_t bytes_mapped = batch_count * page_bytes;
      current_phys += bytes_mapped;
      current_virt += bytes_mapped;
      remaining -= bytes_mapped;
    }

    return true;
  }
};
}  // namespace

AddressSpace* kernel_space = nullptr;

void VirtualManager::initialize(limine_memmap_response* response) noexcept {
  BootTableAllocator alloc;

  arch::initialize_cpu();
  arch::initialize_pat();

  const PhysAddr root_frame = alloc.alloc_table_frame();
  if (root_frame.is_null()) hal::cpu::halt(false);

  kernel_space = new (kernel_space_buffer) AddressSpace(root_frame, false);

  map_hhdm(*kernel_space, alloc, response);
  map_kernel(*kernel_space, alloc);
  vmm_logger.info("Loading Kernel Pagemap at 0x%lx", root_frame.raw());

  kernel_space->load();
}

void VirtualManager::map_hhdm(
    AddressSpace& space,
    IPageTableAllocator& alloc,
    limine_memmap_response* response
) noexcept {
  const VmFlags flags = VmFlags::Read | VmFlags::Write | VmFlags::Global;

  limine_memmap_entry* const* entries = response->entries;
  const std::size_t entry_count       = response->entry_count;

  for (std::size_t i = 0; i < entry_count; ++i) {
    const limine_memmap_entry* entry = entries[i];

    if (entry->type == LIMINE_MEMMAP_RESERVED ||
        entry->type == LIMINE_MEMMAP_BAD_MEMORY ||
        entry->type == LIMINE_MEMMAP_RESERVED_MAPPED)
      continue;

    CacheMode cache = CacheMode::WriteBack;
    if (entry->type == LIMINE_MEMMAP_FRAMEBUFFER)
      cache = CacheMode::WriteCombining;
    if (entry->type == LIMINE_MEMMAP_ACPI_NVS)
      cache = CacheMode::UncacheableStrong;

    const PhysAddr p_base(entry->base);
    const VirtAddr v_base = p_base.to_virt();

    RegionMapper::map(
        space,
        v_base,
        p_base,
        entry->length,
        flags,
        cache,
        alloc
    );
  }
}

void VirtualManager::map_kernel(
    AddressSpace& space,
    IPageTableAllocator& alloc
) noexcept {
  const KernelSegment segments[] = {
      {__limine_requests_start,
       __limine_requests_end,
       VmFlags::Read | VmFlags::Write},
      {__text_start, __text_end, VmFlags::Read | VmFlags::Execute},
      {__rodata_start, __rodata_end, VmFlags::Read},
      {__data_start, __data_end, VmFlags::Read | VmFlags::Write},
      {__bss_start, __bss_end, VmFlags::Read | VmFlags::Write}
  };

  for (const auto& seg : segments) {
    if (seg.size_bytes() == 0) continue;

    const PhysAddr p_base = KaslrMath::to_phys(seg.start());
    const VirtAddr v_base(reinterpret_cast<std::uintptr_t>(seg.start()));
    const VmFlags flags = seg.flags() | VmFlags::Global;

    RegionMapper::map(
        space,
        v_base,
        p_base,
        seg.size_bytes(),
        flags,
        CacheMode::WriteBack,
        alloc
    );
  }
}

bool VirtualManager::map_mmio(VirtAddr virt, PhysAddr phys) noexcept {
  BootTableAllocator alloc;

  return RegionMapper::map(
      *kernel_space,
      virt,
      phys,
      PAGE_SIZE_SMALL,
      VmFlags::Read | VmFlags::Write | VmFlags::Global,
      CacheMode::UncacheableStrong,
      alloc
  );
}
}  // namespace memory
}  // namespace kernel