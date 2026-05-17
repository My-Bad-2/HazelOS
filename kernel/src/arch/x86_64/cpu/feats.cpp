#include "cpu/feats.hpp"

#include <cstdint>

#include "libs/maths.hpp"

namespace kernel {
namespace x86_64 {
namespace cpu {
constexpr FeatureCoordinate ProcessorState::get_feature_coordinate(
    std::size_t index
) noexcept {
  // Every 32 features correspond to a new CPUID register block
  const std::size_t block = index / 32;
  const std::uint8_t bit  = static_cast<std::uint8_t>(index % 32);

  switch (block) {
    case 0:
      return {0x1, 0, TargetRegister::EDX, bit};
    case 1:
      return {0x1, 0, TargetRegister::ECX, bit};
    case 2:
      return {0x00000007, 0, TargetRegister::EBX, bit};
    case 3:
      return {0x00000007, 0, TargetRegister::ECX, bit};
    case 4:
      return {0x00000007, 0, TargetRegister::EDX, bit};
    case 5:
      return {0x00000007, 1, TargetRegister::EAX, bit};
    case 6:
      return {0x80000001, 0, TargetRegister::EDX, bit};
    case 7:
      return {0x80000001, 0, TargetRegister::ECX, bit};
    default:
      return {0, 0, TargetRegister::EAX, 0};
  }
}

void ProcessorState::sanitize_brand_string() noexcept {
  std::size_t start = 0;
  while (start < m_brand_string.size() && m_brand_string[start] == ' ') start++;

  std::size_t end = m_brand_string.size();
  while (end > start &&
         (m_brand_string[end - 1] == '\0' || m_brand_string[end - 1] == ' '))
    end--;

  if (start > 0 && start < end)
    for (std::size_t i = 0; start + i < end; ++i)
      m_brand_string[i] = m_brand_string[start + i];

  m_brand_len = end - start;
}

bool ProcessorState::has_feature(CpuFeature feature) const noexcept {
  const auto index = static_cast<std::size_t>(feature);
  if (index >= static_cast<std::size_t>(CpuFeature::COUNT)) return false;

  const std::size_t word_idx = index / 64;
  const std::size_t bit_idx  = index % 64;

  return libs::maths::has_bits(m_feature_bitset[word_idx], bit_idx);
}

void ProcessorState::gather_address_limits() noexcept {
  if (m_max_extended_leaf >= 0x80000008) {
    const CpuidRegs regs = call_cpuid(0x80000008, 0);

    m_address_limits.physical_bits = regs.eax & 0xff;
    m_address_limits.virtual_bits  = (regs.eax >> 8) & 0xff;
  } else {
    // For super-ancient x86-64 cpus
    m_address_limits.physical_bits = 36;
    m_address_limits.virtual_bits  = 48;
  }
}

void ProcessorState::gather_basic_topology() noexcept {
  if (m_max_basic_leaf >= 1) {
    const CpuidRegs regs = call_cpuid(1, 0);

    m_topology.legacy_apic_id         = (regs.ebx >> 24) & 0xff;
    m_topology.max_logical_processors = (regs.ebx >> 16) & 0xff;
    m_topology.clflush_line_size      = ((regs.ebx >> 8) & 0xff) * 8;

    m_topology.x2apic_id = m_topology.legacy_apic_id;
  }

  // Prefer V2 (0x1f), fallback to V1 (0x0b)
  std::uint32_t topology_leaf = 0;
  if (m_max_basic_leaf >= 0x1f)
    topology_leaf = 0x1f;
  else if (m_max_basic_leaf >= 0x0b)
    topology_leaf = 0x0b;

  if (topology_leaf != 0) {
    std::uint32_t subleaf = 0;

    while (true) {
      const CpuidRegs regs = call_cpuid(topology_leaf, subleaf);

      if (regs.eax == 0 && regs.ebx == 0) break;

      m_topology.x2apic_id              = regs.edx;
      m_topology.max_logical_processors = regs.ebx & 0xffff;
      subleaf++;
    }
  }
}

void ProcessorState::gather_frequencies() noexcept {
  if (m_max_basic_leaf >= 0x16) {
    const CpuidRegs regs = call_cpuid(0x16, 0);

    m_frequencies.base_mhz = regs.eax & 0xffff;
    m_frequencies.max_mhz  = regs.ebx & 0xffff;
    m_frequencies.bus_mhz  = regs.ecx & 0xffff;
  }
}

void ProcessorState::initialize() noexcept {
  // Get max basic leaf and vendor string
  const CpuidRegs regs = call_cpuid(0, 0);
  m_max_basic_leaf     = regs.eax;

  auto* vendor = reinterpret_cast<std::uint32_t*>(m_vendor_string.data());
  vendor[0]    = regs.ebx;
  vendor[1]    = regs.edx;
  vendor[3]    = regs.ecx;

  const CpuidRegs ext_regs = call_cpuid(0x80000000, 0);
  m_max_extended_leaf      = ext_regs.eax;

  if (m_max_extended_leaf >= 0x80000004) {
    auto* brand = reinterpret_cast<std::uint32_t*>(m_brand_string.data());
    std::size_t offset = 0;

    for (std::uint32_t leaf = 0x80000002; leaf <= 0x80000004; ++leaf) {
      const CpuidRegs chunk = call_cpuid(leaf, 0);

      brand[offset++] = chunk.eax;
      brand[offset++] = chunk.ebx;
      brand[offset++] = chunk.ecx;
      brand[offset++] = chunk.edx;
    }

    sanitize_brand_string();
  }

  for (std::size_t block = 0; block < 8; ++block) {
    const FeatureCoordinate coord = get_feature_coordinate(block * 32);

    if ((coord.leaf < 0x80000000 && coord.leaf > m_max_basic_leaf) ||
        (coord.leaf >= 0x80000000 && coord.leaf > m_max_extended_leaf))
      continue;

    const CpuidRegs target_regs = call_cpuid(coord.leaf, coord.subleaf);
    const std::uint32_t reg     = select_registers(target_regs, coord.reg);

    // Block 0, 2, 4... go into the lower 32 bits of their respective words
    // Block 1, 3, 5... go into the upper 32 bits of their respective words
    const std::size_t word_idx  = block / 2;
    const std::size_t bit_shift = (block % 2) * 32;

    m_feature_bitset[word_idx] |=
        (static_cast<std::uint64_t>(reg) << bit_shift);

    gather_address_limits();
    gather_basic_topology();
    gather_frequencies();
  }
}
}  // namespace cpu
}  // namespace x86_64
}  // namespace kernel