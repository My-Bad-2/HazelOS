#include "memory/address/physical.hpp"
#include "memory/address/virtual.hpp"
#include "memory/memory.hpp"

namespace kernel {
namespace memory {
VirtAddr PhysAddr::to_virt() const noexcept {
  if (is_null()) return VirtAddr{0};
  return VirtAddr{to_higher_half(m_addr)};
}

PhysAddr VirtAddr::to_phys() const noexcept {
  if (is_null()) return PhysAddr{~0ul};
  return PhysAddr{from_higher_half(m_addr)};
}
}  // namespace memory
}  // namespace kernel