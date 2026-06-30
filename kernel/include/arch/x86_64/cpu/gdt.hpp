#ifndef KERNEL_INCLUDE_ARCH_CPU_GDT_HPP
#define KERNEL_INCLUDE_ARCH_CPU_GDT_HPP 1

#include <array>
#include <cstdint>
#include <utility>

#include "compiler.h"

namespace kernel {
namespace x86_64 {
namespace cpu {
namespace gdt {
struct __packed TaskStateSegment {
  std::uint32_t reserved0{};
  std::array<std::uint64_t, 3> rsp{};
  std::uint64_t reserved1{};
  std::array<std::uint64_t, 7> ist{};
  std::uint64_t reserved2{};
  std::uint16_t reserved3{};
  std::uint16_t iopb_offset{sizeof(TaskStateSegment)};
};

static_assert(sizeof(TaskStateSegment) == 104, "Invalid TSS size.");

class DescriptorTable {
 private:
  static constexpr std::uint64_t build_segment(
      std::uint32_t base,
      std::uint32_t limit,
      std::uint8_t access,
      std::uint8_t flags
  );

  std::array<std::uint64_t, 8> m_entries{};
  TaskStateSegment m_tss;

 public:
  static std::pair<std::uint64_t, std::uint64_t>
  build_tss(std::uintptr_t tss_base, std::uint32_t tss_limit);

  DescriptorTable();

  DescriptorTable(const DescriptorTable&)            = delete;
  DescriptorTable& operator=(const DescriptorTable&) = delete;

  void load(std::uintptr_t kernel_stack, std::uintptr_t panic_stack);
};
}  // namespace gdt
}  // namespace cpu
}  // namespace x86_64
}  // namespace kernel

#endif