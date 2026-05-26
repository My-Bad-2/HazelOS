#include "memory/memory.hpp"

#include "core/boot.hpp"
#include "memory/pmm.hpp"
#include "memory/vmm.hpp"

namespace kernel {
namespace memory {
void initialize() {
  limine_memmap_response* response = boot::memmap_request.response;
  PhysicalManager::initialize(response);
  VirtualManager::initialize(response);
}
}  // namespace memory
}  // namespace kernel