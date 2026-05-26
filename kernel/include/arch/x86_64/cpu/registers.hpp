#ifndef KERNEL_ARCH_X86_64_CPU_REGISTERS_HPP
#define KERNEL_ARCH_X86_64_CPU_REGISTERS_HPP 1

#include <concepts>
#include <cstdint>

#include "compiler.h"

namespace kernel {
namespace x86_64 {
namespace cpu {
union CR0 {
  std::uint64_t raw;
  struct {
    std::uint64_t protection_enable   : 1;
    std::uint64_t monitor_coprocessor : 1;
    std::uint64_t emulation           : 1;
    std::uint64_t task_switched       : 1;
    std::uint64_t extension_type      : 1;
    std::uint64_t numeric_error       : 1;
    std::uint64_t reserved_1          : 10;
    std::uint64_t write_protect       : 1;
    std::uint64_t reserved_2          : 1;
    std::uint64_t alignment_mask      : 1;
    std::uint64_t reserved_3          : 10;
    std::uint64_t not_write_through   : 1;
    std::uint64_t cache_disable       : 1;
    std::uint64_t paging              : 1;
    std::uint64_t reserved_high       : 32;
  } bits;
};

union CR3 {
  std::uint64_t raw;
  struct {
    std::uint64_t ignored_low      : 3;
    std::uint64_t write_through    : 1;
    std::uint64_t cache_disable    : 1;
    std::uint64_t ignored_mid      : 7;
    std::uint64_t physical_address : 40;
    std::uint64_t ignored_high     : 12;
  } bits;

  struct {
    std::uint64_t pcid             : 12;
    std::uint64_t physical_address : 40;
    std::uint64_t reserved         : 11;
    std::uint64_t no_flush         : 1;
  } pcid;
};

union CR4 {
  std::uint64_t raw;
  struct {
    std::uint64_t vme        : 1;
    std::uint64_t pvi        : 1;
    std::uint64_t tsd        : 1;
    std::uint64_t de         : 1;
    std::uint64_t pse        : 1;
    std::uint64_t pae        : 1;
    std::uint64_t mce        : 1;
    std::uint64_t pge        : 1;
    std::uint64_t pce        : 1;
    std::uint64_t osfxsr     : 1;
    std::uint64_t osxmmexcpt : 1;
    std::uint64_t umip       : 1;
    std::uint64_t la57       : 1;
    std::uint64_t vmxe       : 1;
    std::uint64_t smxe       : 1;
    std::uint64_t reserved_1 : 1;
    std::uint64_t fsgsbase   : 1;
    std::uint64_t pcide      : 1;
    std::uint64_t osxsave    : 1;
    std::uint64_t key_locker : 1;
    std::uint64_t smep       : 1;
    std::uint64_t smap       : 1;
    std::uint64_t pke        : 1;
    std::uint64_t cet        : 1;
    std::uint64_t pks        : 1;
    std::uint64_t uintr      : 1;
    std::uint64_t reserved_2 : 38;
  } bits;
};

union EFER {
  std::uint64_t raw;
  struct {
    std::uint64_t syscall_enable   : 1;
    std::uint64_t reserved_1       : 7;
    std::uint64_t long_mode_enable : 1;
    std::uint64_t reserved_2       : 1;
    std::uint64_t long_mode_active : 1;
    std::uint64_t nx_enable        : 1;
    std::uint64_t svme_enable      : 1;
    std::uint64_t lmsle_enable     : 1;
    std::uint64_t ffxsr_enable     : 1;
    std::uint64_t tce_enable       : 1;
    std::uint64_t reserved_high    : 48;
  } bits;

  static constexpr std::uint32_t MSR_ID = 0xC0000080;
};

template <typename T>
concept IsMsr = requires {
  { T::MSR_ID } -> std::convertible_to<std::uint32_t>;
};

template <typename Reg>
__nodiscard inline Reg read() noexcept;

template <typename Reg>
inline void write(Reg value) noexcept;

template <>
__nodiscard inline CR0 read<CR0>() noexcept {
  std::uint64_t val;
  asm volatile("mov %%cr0, %0" : "=r"(val)::"memory");
  return {.raw = val};
}

template <>
inline void write(CR0 value) noexcept {
  asm volatile("mov %0, %%cr0" ::"r"(value.raw) : "memory");
}

template <>
__nodiscard inline CR3 read<CR3>() noexcept {
  std::uint64_t val;
  asm volatile("mov %%cr3, %0" : "=r"(val)::"memory");
  return {.raw = val};
}

template <>
inline void write(CR3 value) noexcept {
  asm volatile("mov %0, %%cr3" ::"r"(value.raw) : "memory");
}

template <>
__nodiscard inline CR4 read<CR4>() noexcept {
  std::uint64_t val;
  asm volatile("mov %%cr4, %0" : "=r"(val)::"memory");
  return {.raw = val};
}

template <>
inline void write(CR4 value) noexcept {
  asm volatile("mov %0, %%cr4" ::"r"(value.raw) : "memory");
}

template <IsMsr Reg>
__nodiscard inline Reg read() noexcept {
  std::uint32_t low, high;
  asm volatile("rdmsr" : "=a"(low), "=d"(high) : "c"(Reg::MSR_ID) : "memory");
  return {.raw = (static_cast<std::uint64_t>(high) << 32) | low};
}

template <IsMsr Reg>
inline void write(Reg value) noexcept {
  const std::uint32_t low  = value.raw & 0xffffffff;
  const std::uint32_t high = value.raw >> 32;

  asm volatile("wrmsr" ::"a"(low), "d"(high), "c"(Reg::MSR_ID) : "memory");
}

inline void invalidate_page(std::uintptr_t virt_addr) noexcept {
  asm volatile("invlpg %0" ::"m"(*reinterpret_cast<const char*>(virt_addr))
               : "memory");
}

enum class InvpcidType : std::uint8_t {
  Address          = 0,
  SingleContext    = 1,
  AllContexts      = 2,
  AllRetainGlobals = 3,
};

struct alignas(16) InvpcidDescriptor {
  std::uint64_t pcid     : 12;
  std::uint64_t reserved : 52;
  std::uint64_t linear_address;
};

inline void
invalidate_page(InvpcidType type, const InvpcidDescriptor& desc) noexcept {
  asm volatile("invpcid %0, %1" ::"m"(desc),
               "r"(static_cast<std::uint64_t>(type))
               : "memory");
}

inline void flush_cache() noexcept {
  asm volatile("wbinvd" ::: "memory");
}
}  // namespace cpu
}  // namespace x86_64
}  // namespace kernel

#endif