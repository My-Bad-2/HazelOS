#include "memory/vm/entry.hpp"

#include <atomic>
#include <cstdint>

#include "memory/address/physical.hpp"
#include "memory/paging/flags.hpp"

namespace kernel {
namespace memory {
std::uint64_t PageTableEntry::raw() const noexcept {
  return std::atomic_ref<const std::uint64_t>(m_entry).load(
      std::memory_order_acquire
  );
}

bool PageTableEntry::is_present() const noexcept {
  return (raw() & static_cast<std::uint64_t>(arch::PageFlags::Present)) != 0;
}

bool PageTableEntry::has_flags(arch::PageFlags flags) const noexcept {
  const std::uint64_t raw_flags = static_cast<std::uint64_t>(flags);
  return (raw() & raw_flags) == raw_flags;
}

PhysAddr PageTableEntry::get_frame() const noexcept {
  return PhysAddr(raw() & FRAME_MASK);
}

std::uint8_t PageTableEntry::get_pkey() const noexcept {
  return static_cast<std::uint8_t>((raw() & PKEY_MASK) >> 59);
}

std::size_t PageTableEntry::get_flags() const noexcept {
  return raw() & ~FRAME_MASK;
}

void PageTableEntry::add_flags(arch::PageFlags flags) noexcept {
  std::atomic_ref<std::uint64_t>(m_entry).fetch_or(
      static_cast<std::uint64_t>(flags),
      std::memory_order_release
  );
}

void PageTableEntry::remove_flags(arch::PageFlags flags) noexcept {
  std::atomic_ref<std::uint64_t>(m_entry).fetch_and(
      ~static_cast<std::uint64_t>(flags),
      std::memory_order_release
  );
}

void PageTableEntry::set_frame(PhysAddr paddr) noexcept {
  const std::uint64_t aligned_addr = paddr.align_down().raw();
  const std::atomic_ref<std::uint64_t> ref(m_entry);

  std::uint64_t expected = ref.load(std::memory_order_acquire);
  std::uint64_t desired;

  do {
    desired = (expected & ~FRAME_MASK) | (aligned_addr & FRAME_MASK);
  } while (!ref.compare_exchange_weak(
      expected,
      desired,
      std::memory_order_release,
      std::memory_order_relaxed
  ));
}

void PageTableEntry::set(
    PhysAddr paddr,
    arch::PageFlags flags,
    std::uint8_t pkey
) noexcept {
  const std::uint64_t aligned_addr = paddr.align_down().raw();
  const std::uint64_t raw_flags    = static_cast<std::uint64_t>(flags);
  const std::uint64_t raw_pkey = (static_cast<std::uint64_t>(pkey) & 0xf) << 59;

  const std::atomic_ref<std::uint64_t> ref(m_entry);
  std::uint64_t expected = ref.load(std::memory_order_acquire);
  std::uint64_t desired;

  do {
    const std::uint64_t preserved_bits =
        expected & (std::to_underlying(arch::PageFlags::Accessed) |
                    std::to_underlying(arch::PageFlags::Dirty));

    desired =
        (aligned_addr & FRAME_MASK) | raw_flags | raw_pkey | preserved_bits;
  } while (!ref.compare_exchange_weak(
      expected,
      desired,
      std::memory_order_release,
      std::memory_order_relaxed
  ));
}

void PageTableEntry::clear() noexcept {
  std::atomic_ref<std::uint64_t>(m_entry).store(0, std::memory_order_release);
}

bool PageTableEntry::try_set_intermediate(
    PhysAddr paddr,
    arch::PageFlags flags,
    std::uint8_t pkey
) noexcept {
  std::uint64_t expected = 0;
  const std::uint64_t desired =
      (paddr.align_down().raw() & FRAME_MASK) |
      static_cast<std::uint64_t>(flags) |
      ((static_cast<std::uint64_t>(pkey) & 0xf) << 59);

  return std::atomic_ref<std::uint64_t>(m_entry).compare_exchange_strong(
      expected,
      desired,
      std::memory_order_release,
      std::memory_order_relaxed
  );
}
}  // namespace memory
}  // namespace kernel