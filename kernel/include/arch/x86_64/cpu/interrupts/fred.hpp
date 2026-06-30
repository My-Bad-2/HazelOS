#ifndef KERNEL_INCLUDE_ARCH_CPU_INTERRUPTS_FRED_HPP
#define KERNEL_INCLUDE_ARCH_CPU_INTERRUPTS_FRED_HPP 1

#include <bit>
#include <cstdint>

#include "libs/maths.hpp"
#include "memory/memory.hpp"

namespace kernel::x86_64::cpu::interrupts::fred {
union FRED_RSP0 {
  std::uint64_t raw;
  struct {
    std::uint64_t stack_pointer : 64;
  } bits;

  static constexpr std::uint32_t MSR_ID = 0x1CC;
  explicit FRED_RSP0(std::uint64_t val = 0) : raw(val) {}
};

union FRED_RSP1 {
  std::uint64_t raw;
  struct {
    std::uint64_t stack_pointer : 64;
  } bits;

  static constexpr std::uint32_t MSR_ID = 0x1CD;
  explicit FRED_RSP1(std::uint64_t val = 0) : raw(val) {}
};

union FRED_RSP2 {
  std::uint64_t raw;
  struct {
    std::uint64_t stack_pointer : 64;
  } bits;

  static constexpr std::uint32_t MSR_ID = 0x1CE;
  explicit FRED_RSP2(std::uint64_t val = 0) : raw(val) {}
};

union FRED_RSP3 {
  std::uint64_t raw;
  struct {
    std::uint64_t stack_pointer : 64;
  } bits;

  static constexpr std::uint32_t MSR_ID = 0x1CF;
  explicit FRED_RSP3(std::uint64_t val = 0) : raw(val) {}
};

union FRED_STKLVLS {
  std::uint64_t raw;
  struct {
    std::uint64_t divide_error                   : 2;   // Vector 0
    std::uint64_t debug                          : 2;   // Vector 1
    std::uint64_t nmi                            : 2;   // Vector 2
    std::uint64_t breakpoint                     : 2;   // Vector 3
    std::uint64_t overflow                       : 2;   // Vector 4
    std::uint64_t bound_range_exceeded           : 2;   // Vector 5
    std::uint64_t invalid_opcode                 : 2;   // Vector 6
    std::uint64_t device_not_available           : 2;   // Vector 7
    std::uint64_t double_fault                   : 2;   // Vector 8
    std::uint64_t coprocessor_segment_overrun    : 2;   // Vector 9
    std::uint64_t invalid_tss                    : 2;   // Vector 10
    std::uint64_t segment_not_present            : 2;   // Vector 11
    std::uint64_t stack_segment_fault            : 2;   // Vector 12
    std::uint64_t general_protection_fault       : 2;   // Vector 13
    std::uint64_t page_fault                     : 2;   // Vector 14
    std::uint64_t reserved_15                    : 2;   // Vector 15
    std::uint64_t x87_floating_point_error       : 2;   // Vector 16
    std::uint64_t alignment_check                : 2;   // Vector 17
    std::uint64_t machine_check                  : 2;   // Vector 18
    std::uint64_t simd_floating_point_exception  : 2;   // Vector 19
    std::uint64_t virtualization_exception       : 2;   // Vector 20
    std::uint64_t control_protection_exception   : 2;   // Vector 21
    std::uint64_t reserved_22_27                 : 12;  // Vectors 22-27
    std::uint64_t hypervisor_injection_exception : 2;   // Vector 28
    std::uint64_t vmm_communication_exception    : 2;   // Vector 29
    std::uint64_t security_exception             : 2;   // Vector 30
    std::uint64_t reserved_31                    : 2;   // Vector 31
  } bits;

  static constexpr std::uint32_t MSR_ID = 0x1D0;
  explicit FRED_STKLVLS(std::uint64_t val = 0) : raw(val) {}
};

union FRED_SSP1 {
  std::uint64_t raw;
  struct {
    std::uint64_t shadow_stack_pointer : 64;
  } bits;

  static constexpr std::uint32_t MSR_ID = 0x1D1;
  explicit FRED_SSP1(std::uint64_t val = 0) : raw(val) {}
};

union FRED_SSP2 {
  std::uint64_t raw;
  struct {
    std::uint64_t shadow_stack_pointer : 64;
  } bits;

  static constexpr std::uint32_t MSR_ID = 0x1D2;
  explicit FRED_SSP2(std::uint64_t val = 0) : raw(val) {}
};

union FRED_SSP3 {
  std::uint64_t raw;
  struct {
    std::uint64_t shadow_stack_pointer : 64;
  } bits;

  static constexpr std::uint32_t MSR_ID = 0x1D3;
  explicit FRED_SSP3(std::uint64_t val = 0) : raw(val) {}
};

union FRED_CONFIG {
  std::uint64_t raw;
  struct {
    std::uint64_t csl                            : 2;
    std::uint64_t reserved1                      : 1;
    std::uint64_t ssp                            : 1;
    std::uint64_t reserved2                      : 2;
    std::uint64_t reserve_cache_lines            : 3;
    std::uint64_t maskable_interrupt_stack_level : 2;
    std::uint64_t reserved3                      : 1;
    std::uint64_t entry_point_page               : 52;
  } bits;

  static constexpr std::uint32_t MSR_ID = 0x1D4;
  explicit FRED_CONFIG(std::uint64_t val = 0) : raw(val) {}

  constexpr bool set_entry_page(void* page_address) noexcept {
    auto linear_addr = std::bit_cast<std::uintptr_t>(page_address);

    if (!libs::maths::is_aligned(linear_addr, memory::PAGE_SIZE_SMALL))
      return false;

    bits.entry_point_page = (linear_addr >> 12);
    return true;
  }
};
}  // namespace kernel::x86_64::cpu::interrupts::fred

#endif