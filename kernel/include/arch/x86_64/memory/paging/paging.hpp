#ifndef KERNEL_ARCH_MEMORY_PAGING_HPP
#define KERNEL_ARCH_MEMORY_PAGING_HPP 1

#include <cstdint>
#include <utility>

#include "cpu/feats.hpp"
#include "cpu/registers.hpp"
#include "hal/cpu.hpp"
#include "memory/address/physical.hpp"
#include "memory/address/virtual.hpp"
#include "memory/paging/flags.hpp"
#include "memory/vm/asid.hpp"

namespace kernel {
namespace memory {
namespace arch {
union PAT {
  std::uint64_t raw;
  struct {
    std::uint64_t pa0 : 8;  // PAT=0, PCD=0, PWT=0
    std::uint64_t pa1 : 8;  // PAT=0, PCD=0, PWT=1
    std::uint64_t pa2 : 8;  // PAT=0, PCD=1, PWT=0
    std::uint64_t pa3 : 8;  // PAT=0, PCD=1, PWT=1
    std::uint64_t pa4 : 8;  // PAT=1, PCD=0, PWT=0
    std::uint64_t pa5 : 8;  // PAT=1, PCD=0, PWT=1
    std::uint64_t pa6 : 8;  // PAT=1, PCD=1, PWT=0
    std::uint64_t pa7 : 8;  // PAT=1, PCD=1, PWT=1
  } entries;

  static constexpr std::uint32_t MSR_ID = 0x00000277;
};

inline void load_page_directory(
    PhysAddr root,
    std::uint16_t pcid,
    bool preserve_tlb
) noexcept {
  using namespace x86_64::cpu;
  const ProcessorState& state = get_current_state();

  CR3 cr3;
  cr3.raw = 0;

  if (state.has_feature(CpuFeature::PCID)) {
    cr3.pcid.physical_address = (root.raw() >> 12);
    cr3.pcid.pcid             = pcid & 0xfff;
    cr3.pcid.no_flush         = preserve_tlb ? 1 : 0;
  } else {
    cr3.bits.physical_address = (root.raw() >> 12);
  }

  write(cr3);
}

inline void flush_all_pcids() noexcept {
  using namespace x86_64::cpu;
  const ProcessorState& state = get_current_state();

  if (state.has_feature(CpuFeature::INVPCID))
    return invalidate_page(InvpcidType::AllRetainGlobals, {0, 0, 0});

  if (state.has_feature(CpuFeature::PCID)) {
    CR3 cr3           = read<CR3>();
    cr3.pcid.pcid     = 0;
    cr3.pcid.no_flush = 0;
    write(cr3);

    CR4 cr4        = read<CR4>();
    cr4.bits.pcide = 0;
    write(cr4);
    cr4.bits.pcide = 1;
    return write(cr4);
  }

  write(read<CR3>());
}

inline void
flush_remote_page(VirtAddr virt, std::uint16_t target_pcid) noexcept {
  using namespace x86_64::cpu;
  const ProcessorState& state = get_current_state();

  if (state.has_feature(CpuFeature::INVPCID)) {
    InvpcidDescriptor desc{};
    desc.pcid           = target_pcid & 0xfff;
    desc.linear_address = virt.raw();

    return invalidate_page(InvpcidType::Address, desc);
  }

  if (state.has_feature(CpuFeature::PCID)) {
    const CR3 curr_cr3 = read<CR3>();

    if (curr_cr3.pcid.pcid == (target_pcid & 0xfff))
      return invalidate_page(virt.raw());

    // Edge Case: IPI arrived right after a context switch.
    return flush_all_pcids();
  }

  invalidate_page(virt.raw());
}

inline void flush_local_page(VirtAddr virt) noexcept {
  using namespace x86_64::cpu;
  invalidate_page(virt.raw());
}

inline void initialize_cpu() noexcept {
  using namespace x86_64::cpu;
  const ProcessorState& state = get_current_state();

  if (state.has_feature(CpuFeature::NX)) {
    EFER efer           = read<EFER>();
    efer.bits.nx_enable = 1;
    write(efer);
  }

  CR0 cr0                = read<CR0>();
  cr0.bits.write_protect = 1;
  write(cr0);

  CR4 cr4      = read<CR4>();
  cr4.bits.pae = 1;

  if (state.has_feature(CpuFeature::PGE)) cr4.bits.pge = 1;
  if (state.has_feature(CpuFeature::PCID)) cr4.bits.pcide = 1;
  if (state.has_feature(CpuFeature::SMEP)) cr4.bits.smep = 1;
  if (state.has_feature(CpuFeature::SMAP)) cr4.bits.smap = 1;
  if (state.has_feature(CpuFeature::UMIP)) cr4.bits.umip = 1;
  if (state.has_feature(CpuFeature::PKU)) cr4.bits.pke = 1;

  get_current_asid_manager().initialize(flush_all_pcids);
}

inline void initialize_pat() noexcept {
  using namespace x86_64::cpu;

  PAT pat;
  pat.raw = 0;

  // CacheMode::WriteBack
  pat.entries.pa0 = std::to_underlying(PatMemoryType::WriteBack);

  // CacheMode::WriteThrough
  pat.entries.pa1 = std::to_underlying(PatMemoryType::WriteThrough);

  // CacheMode::Uncacheable
  pat.entries.pa2 = std::to_underlying(PatMemoryType::UncachedWeak);

  // CacheMode::UncacheableStrong
  pat.entries.pa3 = std::to_underlying(PatMemoryType::Uncacheable);

  // CacheMode::WriteProtected
  pat.entries.pa4 = std::to_underlying(PatMemoryType::WriteProtected);

  // CacheMode::WriteCombining
  pat.entries.pa5 = std::to_underlying(PatMemoryType::WriteCombining);

  // Unused
  pat.entries.pa6 = std::to_underlying(PatMemoryType::UncachedWeak);
  pat.entries.pa7 = std::to_underlying(PatMemoryType::Uncacheable);

  hal::cpu::disable_interrupts();

  // Flush all internal cpu caches to RAM
  flush_cache();

  write(read<CR3>());
  write(pat);

  flush_cache();
  write(read<CR3>());
}

inline void flush_local_context() noexcept {
  using namespace x86_64::cpu;

  const ProcessorState& state = get_current_state();
  CR3 cr3                     = read<CR3>();

  if (state.has_feature(CpuFeature::INVPCID)) {
    invalidate_page(
        InvpcidType::SingleContext,
        {
            .pcid           = static_cast<std::uint64_t>(cr3.pcid.pcid),
            .reserved       = 0,
            .linear_address = 0,
        }
    );
  } else {
    if (state.has_feature(CpuFeature::PCID)) cr3.pcid.no_flush = 0;
    write(cr3);
  }
}

inline void flush_remote_context(std::uint16_t target_pcid) noexcept {
  using namespace x86_64::cpu;

  const ProcessorState& state = get_current_state();

  if (state.has_feature(CpuFeature::INVPCID)) {
    invalidate_page(
        InvpcidType::SingleContext,
        {
            .pcid           = static_cast<std::uint64_t>(target_pcid & 0xffff),
            .reserved       = 0,
            .linear_address = 0,
        }
    );
  } else if (state.has_feature(CpuFeature::PCID)) {
    CR3 cr3 = read<CR3>();

    if (cr3.pcid.pcid == (target_pcid & 0xffff)) {
      cr3.pcid.no_flush = 0;
      write(cr3);
    } else {
      flush_all_pcids();
    }
  } else {
    write(read<CR3>());
  }
}
}  // namespace arch
}  // namespace memory
}  // namespace kernel

#endif