#include "cpu/feats.hpp"

#include <cstdint>
#include <string_view>

#include "libs/maths.hpp"

namespace kernel {
namespace x86_64 {
namespace cpu {
bool ProcessorState::has_feature(CpuFeature feature) const noexcept {
  const auto index = static_cast<std::size_t>(feature);
  if (index >= static_cast<std::size_t>(CpuFeature::COUNT)) return false;

  const std::size_t word_idx = index / 64;
  const std::size_t bit_idx  = index % 64;

  return libs::maths::has_bits(m_feature_bitset[word_idx], bit_idx);
}

void ProcessorState::fetch_vendor_and_max_leafs() noexcept {
  const CpuidRegs regs = call_cpuid(0, 0);
  m_max_basic_leaf     = regs.eax;

  auto* vendor = reinterpret_cast<std::uint32_t*>(m_vendor_string.data());
  vendor[0]    = regs.ebx;
  vendor[1]    = regs.edx;
  vendor[2]    = regs.ecx;

  const std::string_view v_str = vendor_string();
  if (v_str == "GenuineIntel")
    m_vendor = CpuVendor::Intel;
  else if (v_str == "AuthenticAMD")
    m_vendor = CpuVendor::AMD;
  else
    m_vendor = CpuVendor::Unknown;

  const CpuidRegs regs_ext = call_cpuid(0x80000000, 0);
  m_max_basic_leaf         = regs_ext.eax;
}

void ProcessorState::fetch_brand_string() noexcept {
  if (m_max_extended_leaf < 0x80000004) return;

  auto* brand        = reinterpret_cast<std::uint32_t*>(m_brand_string.data());
  std::size_t offset = 0;
  for (std::uint32_t leaf = 0x80000002; leaf <= 0x80000004; ++leaf) {
    const CpuidRegs chunk = call_cpuid(leaf, 0);
    brand[offset++]       = chunk.eax;
    brand[offset++]       = chunk.ebx;
    brand[offset++]       = chunk.ecx;
    brand[offset++]       = chunk.edx;
  }

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

void ProcessorState::fetch_address_limits() noexcept {
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

void ProcessorState::fetch_features() noexcept {
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
  }
}

void ProcessorState::fetch_extended_topology() noexcept {
  std::uint32_t topology_leaf = 0;
  if (m_max_basic_leaf >= 0x1f)
    topology_leaf = 0x1f;
  else if (m_max_basic_leaf >= 0x0b)
    topology_leaf = 0x0b;

  if (topology_leaf == 0) {
    if (m_max_basic_leaf >= 1) {
      const CpuidRegs regs = call_cpuid(1, 0);
      m_x2apic_id          = (regs.ebx >> 24) & 0xff;
    }

    return;
  }

  std::uint32_t subleaf  = 0;
  m_topology_level_count = 0;

  while (m_topology_level_count < m_topology_levels.size()) {
    auto regs = call_cpuid(topology_leaf, subleaf);

    const std::uint8_t type = (regs.ecx >> 8) & 0xff;
    if (type == 0) break;

    m_x2apic_id = regs.edx;

    TopologyLevel& level     = m_topology_levels[m_topology_level_count];
    level.type               = static_cast<TopologyLevelType>(type);
    level.logical_processors = regs.ebx & 0xFFFF;
    level.shift_mask         = regs.eax & 0x1F;

    m_topology_level_count++;
    subleaf++;
  }
}

void ProcessorState::fetch_cache_hierarchy() noexcept {
  std::uint32_t cache_leaf = 0;

  if (m_vendor == CpuVendor::Intel && m_max_basic_leaf >= 4)
    cache_leaf = 4;
  else if (m_vendor == CpuVendor::AMD && m_max_extended_leaf >= 0x8000001d)
    cache_leaf = 0x8000001d;

  if (cache_leaf == 0) return;

  std::uint32_t subleaf = 0;
  m_cache_count         = 0;

  while (m_cache_count < m_caches.size()) {
    const CpuidRegs regs = call_cpuid(cache_leaf, subleaf);

    const std::uint8_t type = regs.eax & 0x1F;
    if (type == 0) break;  // End of caches

    auto& cache = m_caches[m_cache_count];
    cache.type  = static_cast<CacheType>(type);
    cache.level = (regs.eax >> 5) & 0x07;

    const std::uint32_t ways       = ((regs.ebx >> 22) & 0x3FF) + 1;
    const std::uint32_t partitions = ((regs.ebx >> 12) & 0x3FF) + 1;
    const std::uint32_t line_size  = (regs.ebx & 0xFFF) + 1;
    const std::uint32_t sets       = regs.ecx + 1;

    cache.ways_of_associativity = ways;
    cache.line_size             = line_size;
    cache.sets                  = sets;
    cache.size_bytes            = ways * partitions * line_size * sets;
    cache.is_fully_inclusive    = (regs.edx & (1 << 1)) != 0;

    m_cache_count++;
    subleaf++;
  }
}

void ProcessorState::fetch_frequencies() noexcept {
  if (m_max_basic_leaf >= 0x16) {
    const CpuidRegs regs = call_cpuid(0x16, 0);

    m_frequencies.base_mhz = regs.eax & 0xffff;
    m_frequencies.max_mhz  = regs.ebx & 0xffff;
    m_frequencies.bus_mhz  = regs.ecx & 0xffff;
  }
}
}  // namespace cpu
}  // namespace x86_64
}  // namespace kernel