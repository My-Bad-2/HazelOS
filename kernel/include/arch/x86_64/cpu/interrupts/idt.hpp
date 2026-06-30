#ifndef KERNEL_INCLUDE_ARCH_CPU_INTERRUPTS_IDT_HPP
#define KERNEL_INCLUDE_ARCH_CPU_INTERRUPTS_IDT_HPP 1

#include <array>
#include <utility>

#include "compiler.h"
#include "cpu/interrupts/common.hpp"

namespace kernel::x86_64::cpu::interrupts::idt {
enum class GateType : std::uint8_t { Interrupt = 0xe, Trap = 0xf };

enum class IstIndex : std::uint8_t { NONE, IST1, IST2, IST3 };

struct alignas(16) Descriptor {
  std::uint16_t offset_low;
  std::uint16_t segment_selector;
  std::uint8_t ist;
  std::uint8_t attributes;
  std::uint16_t offset_mid;
  std::uint32_t offset_high;
  std::uint32_t reserved;

  __nodiscard static constexpr Descriptor create(
      void (*handler)(),
      std::uint16_t kernel_cs,
      GateType type      = GateType::Interrupt,
      PrivilegeLevel dpl = PrivilegeLevel::RING0,
      IstIndex ist       = IstIndex::NONE
  ) noexcept {
    auto offset = std::bit_cast<std::uintptr_t>(handler);

    Descriptor entry{};
    entry.offset_low       = static_cast<std::uint16_t>(offset & 0xffff);
    entry.segment_selector = kernel_cs;
    entry.ist              = std::to_underlying(ist) & 0x07;
    entry.attributes =
        (1 << 7) | (std::to_underlying(dpl) << 5) | std::to_underlying(type);
    entry.offset_mid  = static_cast<std::uint16_t>((offset >> 16) & 0xffff);
    entry.offset_high = static_cast<std::uint32_t>((offset >> 32) & 0xffffffff);
    entry.reserved    = 0;
    return entry;
  }
};

template <std::size_t N = 256>
class Table {
 private:
  std::array<Descriptor, N> m_entries{};

 public:
  consteval Table() = default;

  constexpr void set_handler(
      std::size_t vector,
      void (*handler)(),
      std::uint16_t cs,
      GateType type      = GateType::Interrupt,
      PrivilegeLevel dpl = PrivilegeLevel::RING0,
      IstIndex ist       = IstIndex::NONE
  ) noexcept {
    if (vector < N)
      m_entries[vector] = Descriptor::create(handler, cs, type, dpl, ist);
  }

  void load() const noexcept {
    struct __packed Register {
      std::uint16_t limit;
      const void* base;
    };

    Register idtr{
        .limit = static_cast<std::uint16_t>(sizeof(Descriptor) * N - 1),
        .base  = m_entries.data(),
    };

    asm volatile("lidt %0" ::"m"(idtr) : "memory");
  }
};
}  // namespace kernel::x86_64::cpu::interrupts::idt

#endif