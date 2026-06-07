#include "memory/address_space.hpp"

#include <atomic>
#include <cstdint>
#include <utility>

#include "core/logger.hpp"
#include "cpu/feats.hpp"
#include "hal/smp.hpp"
#include "memory/address/physical.hpp"
#include "memory/address/virtual.hpp"
#include "memory/paging/flags.hpp"
#include "memory/paging/paging.hpp"
#include "memory/vm/PageTableAllocator.hpp"
#include "memory/vm/asid.hpp"
#include "memory/vm/flags.hpp"

namespace kernel {
namespace memory {
namespace {
log::Logger paging_logger{"PAGING", log::Level::Debug};
AsidManager asid_manager;

struct VamMath {
  static constexpr std::uint8_t level_shift(std::uint8_t level) noexcept {
    return 12 + ((level - 1) * 9);
  }

  static constexpr std::uint16_t
  index_at(VirtAddr virt, std::uint8_t level) noexcept {
    return (virt.raw() >> level_shift(level)) & 0x1ff;
  }

  static constexpr std::uint64_t span_at(std::uint8_t level) noexcept {
    return 1ul << level_shift(level);
  }
};

constexpr arch::PageFlags translate_flags(VmFlags vm, CacheMode cache) {
  arch::PageFlags flags = arch::PageFlags::None;

  const arch::PageFlags pat_bit = ((vm & VmFlags::Huge) != VmFlags::None)
                                      ? arch::PageFlags::LargePat
                                      : arch::PageFlags::Pat;

  if ((vm & VmFlags::Read) != VmFlags::None)
    flags = flags | arch::PageFlags::Present;

  if ((vm & VmFlags::Write) != VmFlags::None)
    flags = flags | arch::PageFlags::Write;

  if ((vm & VmFlags::Execute) == VmFlags::None)
    flags = flags | arch::PageFlags::NoExecute;

  if ((vm & VmFlags::Global) != VmFlags::None)
    flags = flags | arch::PageFlags::Global;

  if ((vm & VmFlags::User) != VmFlags::None)
    flags = flags | arch::PageFlags::User;

  if ((vm & VmFlags::Huge) != VmFlags::None)
    flags = flags | arch::PageFlags::Huge;

  switch (cache) {
    case CacheMode::Uncacheable:
      flags = flags | arch::PageFlags::CacheDisable;
      break;
    case CacheMode::UncacheableStrong:
      flags =
          flags | arch::PageFlags::CacheDisable | arch::PageFlags::WriteThrough;
      break;
    case CacheMode::WriteThrough:
      flags = flags | arch::PageFlags::WriteThrough;
      break;
    case CacheMode::WriteProtected:
      flags = flags | pat_bit;
      break;
    case CacheMode::WriteCombining:
      flags = flags | pat_bit | arch::PageFlags::WriteThrough;
      break;
    case CacheMode::WriteBack:
    default:
      break;
  }

  return flags;
}
}  // namespace

AddressSpace::AddressSpace(PhysAddr root_phys, bool uses_pml5) noexcept
    : m_root_phys(root_phys), m_max_level(uses_pml5 ? 5 : 4) {}

PageTable* AddressSpace::walk_to_table(
    VirtAddr virt,
    std::uint8_t target_level,
    IPageTableAllocator* alloc
) noexcept {
  PhysAddr curr_phys = m_root_phys;

  for (std::uint8_t level = m_max_level; level > target_level; --level) {
    const std::uint16_t idx = VamMath::index_at(virt, level);
    PageTable* table        = curr_phys.to_virt().as<PageTable>();
    PageTableEntry& entry   = (*table)[idx];

    if (!entry.is_present()) {
      if (!alloc) return nullptr;

      const PhysAddr new_frame = alloc->alloc_table_frame();
      if (new_frame.is_null()) return nullptr;

      PageTable* new_table = new_frame.to_virt().as<PageTable>();
      new_table->clear_entries();

      const arch::PageFlags dir_flags = arch::PageFlags::Present |
                                        arch::PageFlags::Write |
                                        arch::PageFlags::User;
      if (!entry.try_set_intermediate(new_frame, dir_flags))
        alloc->free_table_frame(new_frame);
    } else if (entry.has_flags(arch::PageFlags::Huge)) {
      return nullptr;
    }

    curr_phys = entry.get_frame();
  }

  return curr_phys.to_virt().as<PageTable>();
}

void AddressSpace::destroy_table(
    PhysAddr table_phys,
    std::uint8_t curr_level,
    bool is_root,
    IPageTableAllocator& alloc
) noexcept {
  PageTable* table          = table_phys.to_virt().as<PageTable>();
  const std::size_t end_idx = is_root ? 256 : 512;

  for (std::size_t i = 0; i < end_idx; ++i) {
    PageTableEntry& entry = (*table)[i];

    if (entry.is_present() && !entry.has_flags(arch::PageFlags::Huge)) {
      if (curr_level > 1) {
        destroy_table(entry.get_frame(), curr_level - 1, false, alloc);
        alloc.free_table_frame(entry.get_frame());
      }

      entry.clear();
    }
  }
}

bool AddressSpace::map_range(
    VirtAddr start_virt,
    PhysAddr start_phys,
    std::size_t count,
    VmFlags vm,
    CacheMode cache,
    PageSize size,
    std::uint8_t pkey,
    IPageTableAllocator& alloc
) noexcept {
  using namespace x86_64::cpu;
  if (count == 0) return true;

  if (size == PageSize::Size1GB &&
      !get_current_state().has_feature(CpuFeature::GIGAPAGE)) {
    // 1GB pages are unsupported by the CPU. So, downgrade to 2MB pages and
    // scale up the count (1GB = 2MB * 512)
    size = PageSize::Size2MB;
    count *= 512;
  }

  if (size != PageSize::Size4KB) vm = vm | VmFlags::Huge;

  const std::uint8_t target_level = static_cast<std::uint8_t>(size);
  const std::uint64_t page_bytes  = VamMath::span_at(target_level);
  const arch::PageFlags flags     = translate_flags(vm, cache);

  paging_logger.debug(
      "Mapping 0x%016lx -> 0x%016lx | Flags = 0x%016lx | size = 0x%lx bytes",
      start_phys.raw(),
      start_virt.raw(),
      flags,
      count * page_bytes
  );

  VirtAddr current_virt    = start_virt;
  PhysAddr current_phys    = start_phys;
  std::size_t pages_mapped = 0;

  while (pages_mapped < count) {
    PageTable* table = walk_to_table(current_virt, target_level, &alloc);
    if (!table) {
      paging_logger.fatal("Out of Memory mid-mapping!");
      return false;
    }

    const std::uint16_t start_idx =
        VamMath::index_at(current_virt, target_level);

    // How many pages can be mapped before we hit the end of this tabel
    const std::size_t pages_left     = count - pages_mapped;
    const std::size_t slots_in_table = 512 - start_idx;
    const std::size_t batch_count    = std::min(pages_left, slots_in_table);

    for (size_t i = 0; i < batch_count; ++i) {
      (*table)[start_idx + i]
          .set(current_phys, flags | arch::PageFlags::Present, pkey);

      current_phys += page_bytes;
      current_virt += page_bytes;
    }

    pages_mapped += batch_count;
  }

  return true;
}

bool AddressSpace::unmap_range(
    VirtAddr start_virt,
    std::size_t count,
    PageSize size
) noexcept {
  using namespace x86_64::cpu;
  if (count == 0) return true;

  if (size == PageSize::Size1GB &&
      !get_current_state().has_feature(CpuFeature::GIGAPAGE)) {
    size = PageSize::Size2MB;
    count *= 512;
  }

  const std::uint8_t target_level = static_cast<std::uint8_t>(size);
  const std::uint64_t page_bytes  = VamMath::span_at(target_level);

  paging_logger.debug(
      "Unmapping 0x%016lx | size = 0x%lx bytes",
      start_virt.raw(),
      page_bytes
  );

  VirtAddr current_virt      = start_virt;
  std::size_t pages_unmapped = 0;

  while (pages_unmapped < count) {
    PageTable* table = walk_to_table(current_virt, target_level, nullptr);

    const std::uint16_t start_idx =
        VamMath::index_at(current_virt, target_level);

    const std::size_t pages_left     = count - pages_unmapped;
    const std::size_t slots_in_table = 512 - start_idx;
    const std::size_t batch_count    = std::min(pages_left, slots_in_table);

    if (table)
      for (std::size_t i = 0; i < batch_count; ++i)
        (*table)[start_idx + i].clear();

    current_virt += (batch_count * page_bytes);
    pages_unmapped += batch_count;
  }

  if (count > 64) {
    dispatch_tlb_shootdown_context();
  } else {
    VirtAddr shootdown_virt = start_virt;
    for (std::size_t i = 0; i < count; ++i) {
      dispatch_tlb_shootdown(shootdown_virt);
      shootdown_virt += page_bytes;
    }
  }

  return true;
}

PhysAddr AddressSpace::resolve(VirtAddr virt) const noexcept {
  PhysAddr current_phys = m_root_phys;

  for (std::uint8_t level = m_max_level; level > 0; --level) {
    const std::uint16_t idx     = VamMath::index_at(virt, level);
    const PageTable* table      = current_phys.to_virt().as<PageTable>();
    const PageTableEntry& entry = (*table)[idx];

    if (!entry.is_present()) return PhysAddr(0);

    if (level == 1 || entry.has_flags(arch::PageFlags::Huge)) {
      const std::uint64_t page_mask = VamMath::span_at(level) - 1;
      const std::uint64_t offset    = virt.raw() & page_mask;

      return PhysAddr(entry.get_frame().raw() + offset);
    }

    current_phys = entry.get_frame();
  }

  return PhysAddr(0);
}

void AddressSpace::dispatch_tlb_shootdown(VirtAddr virt) noexcept {
  const std::uint32_t current_core = 0;
  const std::size_t word_idx       = current_core / 64;
  const std::uint64_t bit          = 1ul << (current_core % 64);

  const std::uint64_t local_active =
      m_active_cpus[word_idx].load(std::memory_order_relaxed);
  if (local_active) arch::flush_local_page(virt);

  std::array<std::uint64_t, MASK_WORDS> ipi_mask = {};

  bool has_remote_cores = false;

  for (std::size_t i = 0; i < MASK_WORDS; ++i) {
    ipi_mask[i] = m_active_cpus[i].load(std::memory_order_relaxed);

    if (i == word_idx) ipi_mask[i] &= ~bit;
    if (ipi_mask[i] != 0) has_remote_cores = true;
  }

  if (has_remote_cores) {
    // Send shootdown IPI (ipi_mask, MASK_WORDS, virt)
  }
}

void AddressSpace::dispatch_tlb_shootdown_context() noexcept {
  const std::uint32_t current_core = 0;
  const std::size_t word_idx       = current_core / 64;
  const std::uint64_t bit          = 1ul << (current_core % 64);

  const std::uint64_t local_active =
      m_active_cpus[word_idx].load(std::memory_order_relaxed) & bit;
  if (local_active) arch::flush_local_context();

  std::array<std::uint64_t, MASK_WORDS> ipi_mask = {};

  bool has_remote_cores = false;

  for (std::size_t i = 0; i < MASK_WORDS; ++i) {
    ipi_mask[i] = m_active_cpus[i].load(std::memory_order_relaxed);

    if (i == word_idx) ipi_mask[i] &= ~bit;
    if (ipi_mask[i] != 0) has_remote_cores = true;
  }

  if (has_remote_cores) {
    // Send TLB shootdown context ipi (cpu_ipi_mask, word_count)
  }
}

void AddressSpace::handle_shootdown_context_ipi() noexcept {
  const std::uint32_t core_id = hal::smp::get_current_core_id();
  const auto [pcid, epoch]    = m_pcid_cache[core_id];

  if (epoch != get_current_asid_manager().get_epoch()) return;
  arch::flush_remote_context(pcid);
}

void AddressSpace::handle_shootdown_ipi(VirtAddr virt) noexcept {
  const std::uint32_t core_id = hal::smp::get_current_core_id();
  const auto [pcid, epoch]    = m_pcid_cache[core_id];

  if (epoch != get_current_asid_manager().get_epoch()) return;
  arch::flush_remote_page(virt, pcid);
}

void AddressSpace::destroy(IPageTableAllocator& alloc) noexcept {
  destroy_table(m_root_phys, m_max_level, true, alloc);
  alloc.free_table_frame(m_root_phys);
  m_root_phys = PhysAddr(0);
}

void AddressSpace::load() noexcept {
  // Replace it with current core id function
  const std::uint32_t core_id = hal::smp::get_current_core_id();
  mark_active(core_id);

  AsidManager& manager = get_current_asid_manager();
  CacheEntry& cache    = m_pcid_cache[core_id];

  bool preserve_tlb = true;

  if (cache.second != manager.get_epoch()) {
    const CacheEntry new_cache = manager.allocate();

    cache.first  = new_cache.first;   // Pcid
    cache.second = new_cache.second;  // Epoch
    preserve_tlb = false;
  }

  arch::load_page_directory(m_root_phys, cache.first, preserve_tlb);
}

bool AddressSpace::remap_range(
    VirtAddr start_virt,
    PhysAddr start_phys,
    std::size_t count,
    VmFlags vm,
    CacheMode cache,
    PageSize size,
    std::uint8_t pkey,
    IPageTableAllocator& alloc
) noexcept {
  using namespace x86_64::cpu;
  if (count == 0) return true;

  if (size == PageSize::Size1GB &&
      get_current_state().has_feature(CpuFeature::GIGAPAGE)) {
    size = PageSize::Size2MB;
    count *= 512;
  }

  if (size != PageSize::Size4KB) vm = vm | VmFlags::Huge;

  const std::uint8_t target_level = std::to_underlying(size);
  const std::size_t page_bytes    = VamMath::span_at(target_level);
  const arch::PageFlags flags     = translate_flags(vm, cache);

  paging_logger.debug(
      "Remapping 0x%016lx -> 0x%016lx | Flags = 0x%lx",
      start_virt.raw(),
      start_phys.raw(),
      flags
  );

  VirtAddr current_virt    = start_virt;
  PhysAddr current_phys    = start_phys;
  std::size_t pages_mapped = 0;

  while (pages_mapped < count) {
    PageTable* table = walk_to_table(start_virt, target_level, &alloc);
    if (!table) {
      paging_logger.fatal("Out of Memory mid-remapping!");
      return false;
    }

    const std::uint16_t start_idx = VamMath::index_at(start_virt, target_level);

    const std::size_t pages_left     = count - pages_mapped;
    const std::size_t slots_in_table = 512 - start_idx;
    const std::size_t batch_count    = std::min(pages_left, slots_in_table);

    for (std::size_t i = 0; i < batch_count; ++i) {
      (*table)[i].set(start_phys, flags, pkey);

      arch::flush_local_page(current_virt);

      current_phys += page_bytes;
      current_virt += page_bytes;
    }

    pages_mapped += batch_count;
  }

  if (count > 64) {
    dispatch_tlb_shootdown_context();
  } else {
    VirtAddr shootdown_virt = start_virt;
    for (std::size_t i = 0; i < count; ++i) {
      dispatch_tlb_shootdown(shootdown_virt);
      shootdown_virt += page_bytes;
    }
  }

  return true;
}

AsidManager& get_current_asid_manager() noexcept {
  return asid_manager;
}

void AddressSpace::sync_kernel_half(const AddressSpace& space) noexcept {
  PageTable* dest_root      = m_root_phys.to_virt().as<PageTable>();
  const PageTable* src_root = space.get_root().to_virt().as<PageTable>();

  // 0-255 => Userspace || 255-511 => Kernel space
  constexpr std::size_t KERNEL_START_IDX = 256;
  constexpr std::size_t TABLE_ENTRIES    = 512;

  for (std::size_t i = KERNEL_START_IDX; i < TABLE_ENTRIES; ++i)
    (*dest_root)[i] = (*src_root)[i];
}

bool AddressSpace::create_userspace(
    AddressSpace* dest,
    const AddressSpace& master_kernel_space,
    IPageTableAllocator& alloc,
    bool uses_pml5
) noexcept {
  if (!dest) return false;

  const PhysAddr root_frame = alloc.alloc_table_frame();
  if (root_frame.is_null()) return false;

  PageTable* new_root = root_frame.to_virt().as<PageTable>();
  new_root->clear_entries();

  new (dest) AddressSpace(root_frame, uses_pml5);
  dest->sync_kernel_half(master_kernel_space);

  return true;
}

bool AddressSpace::clone_table_recursive(
    PhysAddr src_phys,
    PhysAddr dest_phys,
    std::uint8_t level,
    bool is_root,
    IPageTableAllocator& alloc,
    arch::PageFlags clear_mask,
    arch::PageFlags set_mask
) const noexcept {
  const PageTable* src_table = src_phys.to_virt().as<PageTable>();
  PageTable* dest_table      = dest_phys.to_virt().as<PageTable>();

  const std::size_t end_idx = is_root ? 256 : 512;

  for (std::size_t i = 0; i < end_idx; ++i) {
    const PageTableEntry& src_entry = (*src_table)[i];

    if (!src_entry.is_present()) continue;

    if (level == 1 || src_entry.has_flags(arch::PageFlags::Huge)) {
      std::uint64_t raw_flags = src_entry.get_flags();
      raw_flags &= ~std::to_underlying(clear_mask);
      raw_flags |= std::to_underlying(set_mask);

      (*dest_table)[i].set(
          src_entry.get_frame(),
          static_cast<arch::PageFlags>(raw_flags),
          src_entry.get_pkey()
      );
    } else {
      const PhysAddr new_dir = alloc.alloc_table_frame();
      if (new_dir.is_null()) return false;

      PageTable* new_dir_virt = new_dir.to_virt().as<PageTable>();
      new_dir_virt->clear_entries();

      (*dest_table)[i]
          .set(new_dir, static_cast<arch::PageFlags>(src_entry.get_flags()), 0);

      if (!clone_table_recursive(
              src_entry.get_frame(),
              new_dir,
              level - 1,
              false,
              alloc,
              clear_mask,
              set_mask
          ))
        return false;
    }
  }

  return true;
}

bool AddressSpace::clone_userspace_into(
    AddressSpace* dest,
    IPageTableAllocator& alloc,
    VmFlags clear_mask,
    VmFlags set_mask
) const noexcept {
  if (!dest) return false;

  dest->sync_kernel_half(*this);

  const bool success = clone_table_recursive(
      m_root_phys,
      dest->get_root(),
      m_max_level,
      true,
      alloc,
      translate_flags(clear_mask, CacheMode::WriteBack),
      translate_flags(set_mask, CacheMode::WriteBack)
  );

  if (!success) return false;

  if (static_cast<std::uint64_t>(clear_mask) != 0)
    const_cast<AddressSpace*>(this)->dispatch_tlb_shootdown_context();

  return true;
}
}  // namespace memory
}  // namespace kernel