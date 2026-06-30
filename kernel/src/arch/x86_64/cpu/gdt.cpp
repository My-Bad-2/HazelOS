#include "cpu/gdt.hpp"

#include <cstdint>

#include "core/log_sink.hpp"
#include "core/logger.hpp"
#include "cpu/feats.hpp"
#include "cpu/interrupts/fred.hpp"
#include "cpu/registers.hpp"
#include "cpu/smp.hpp"

namespace kernel {
namespace x86_64 {
namespace cpu {
namespace gdt {
namespace {
enum Access : std::uint8_t {
  PRESENT    = 1 << 7,
  RING_0     = 0 << 5,
  RING_3     = 3 << 5,
  CODE_DATA  = 1 << 4,
  EXECUTABLE = 1 << 3,
  READ_WRITE = 1 << 1,
};

enum Flags : std::uint8_t {
  PAGE_GRANULARITY = 1 << 3,
  SIZE_32          = 1 << 2,
  LONG_MODE        = 1 << 1,
};

struct __packed RegisterPointer {
  std::uint16_t limit;
  const void* base;
};

log::Logger gdt_logger{"GDT", log::Level::Debug};
}  // namespace

constexpr std::uint64_t DescriptorTable::build_segment(
    std::uint32_t base,
    std::uint32_t limit,
    std::uint8_t access,
    std::uint8_t flags
) {
  std::uint64_t ret = (static_cast<std::uint64_t>(base) & 0xff000000) << 32;
  ret |= (static_cast<std::uint64_t>(flags) & 0x0f) << 52;
  ret |= (static_cast<std::uint64_t>(limit) & 0x000f0000) << 32;
  ret |= (static_cast<std::uint64_t>(access) & 0xff) << 40;
  ret |= (static_cast<std::uint64_t>(base) & 0x00ffffff) << 16;
  ret |= static_cast<std::uint64_t>(limit) & 0x0000ffff;

  return ret;
}

std::pair<std::uint64_t, std::uint64_t>
DescriptorTable::build_tss(std::uintptr_t tss_base, std::uint32_t tss_limit) {
  constexpr std::uint8_t tss_access = Access::PRESENT | Access::RING_0 | 0x9;

  std::uint64_t low = build_segment(
      static_cast<std::uint32_t>(tss_base),
      tss_limit,
      tss_access,
      0
  );
  std::uint64_t high = static_cast<std::uint64_t>(tss_base >> 32);

  return {low, high};
}

DescriptorTable::DescriptorTable() {
  // 0x00: Null
  m_entries[0] = 0;

  // 0x08: Kernel Code
  m_entries[1] = build_segment(
      0,
      0,
      Access::PRESENT | Access::RING_0 | Access::CODE_DATA |
          Access::EXECUTABLE | Access::READ_WRITE,
      Flags::LONG_MODE | Flags::PAGE_GRANULARITY
  );

  // 0x10: Kernel Data
  m_entries[2] = build_segment(
      0,
      0,
      Access::PRESENT | Access::RING_0 | Access::CODE_DATA | Access::READ_WRITE,
      Flags::PAGE_GRANULARITY
  );

  // 0x18: User Code 32
  m_entries[3] = build_segment(
      0,
      0xfffff,
      Access::PRESENT | Access::RING_3 | Access::CODE_DATA |
          Access::EXECUTABLE | Access::READ_WRITE,
      Flags::SIZE_32 | Flags::PAGE_GRANULARITY
  );

  // 0x20: User Data
  m_entries[4] = build_segment(
      0,
      0,
      Access::PRESENT | Access::RING_3 | Access::CODE_DATA | Access::READ_WRITE,
      Flags::PAGE_GRANULARITY
  );

  // 0x28: User Code 64
  m_entries[5] = build_segment(
      0,
      0,
      Access::PRESENT | Access::RING_3 | Access::CODE_DATA |
          Access::EXECUTABLE | Access::READ_WRITE,
      Flags::PAGE_GRANULARITY | Flags::LONG_MODE
  );

  auto [low, high] = build_tss(
      reinterpret_cast<std::uintptr_t>(&m_tss),
      sizeof(TaskStateSegment) - 1
  );

  m_entries[6] = low;   // 0x30
  m_entries[7] = high;  // 0x38
}

void DescriptorTable::load(
    std::uintptr_t kernel_stack,
    std::uintptr_t panic_stack
) {
  RegisterPointer gdtr{
      .limit = static_cast<std::uint16_t>(sizeof(m_entries) - 1),
      .base  = m_entries.data()
  };

  asm volatile("lgdt %0" ::"m"(gdtr) : "memory");

  // Release segment registers.
  asm volatile(
      "mov $0x00, %%ax \n"
      "mov %%ax, %%ds \n"
      "mov %%ax, %%es \n"
      "mov $0x10, %%ax \n"  // 0x10: Kernel Data
      "mov %%ax, %%ss \n"
      "pushq $0x08 \n"           // Push Ring 0 CS
      "lea 1f(%%rip), %%rax \n"  // Push target RIP
      "pushq %%rax \n"
      "lretq \n"  // Far return to reload CS
      "1: \n"
      :
      :
      : "rax", "memory"
  );

  // 0x30: byte offset of entry 6
  asm volatile("ltr %%ax" ::"a"(0x30) : "memory");

  auto& state = hal::smp::get_cpu_state().processor_state;
  if (state.has_feature(x86_64::cpu::CpuFeature::FRED)) {
    using namespace interrupts::fred;

    FRED_RSP0 rsp0{kernel_stack};
    FRED_RSP1 rsp1{panic_stack};

    write(rsp0);
    write(rsp1);
  } else {
    m_tss.rsp[0] = kernel_stack;  // Ring 3 -> Ring 0 interrupts
    m_tss.ist[0] = panic_stack;   // IST 1 stack

    STAR star;
    // syscall_cs_ss = Ring 0 CS (0x08), Ring 0 SS (0x10)
    // sysret_cs_ss = Ring 3 CS (0x18), Ring 3 SS (0x20)
    star.bits.syscall_cs_ss = 0x08;
    star.bits.sysret_cs_ss  = 0x18;
    write(star);
  }
}
}  // namespace gdt
}  // namespace cpu
}  // namespace x86_64
}  // namespace kernel
