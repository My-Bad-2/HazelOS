#include <uacpi/kernel_api.h>

#include "core/boot.hpp"
#include "core/logger.hpp"
#include "memory/memory.hpp"
#include "uacpi/log.h"
#include "uacpi/platform/types.h"
#include "uacpi/status.h"

namespace {
kernel::log::Logger uacpi_logger{"UACPI"};
}

extern "C" {
void* uacpi_kernel_map(uacpi_phys_addr addr, uacpi_size) {
  // Physical address is most likely already mapped to higher half map
  return reinterpret_cast<void*>(kernel::memory::to_higher_half(addr));
}

void uacpi_kernel_unmap(void*, uacpi_size) {
  // Don't care about unmapping
}

void uacpi_kernel_log(uacpi_log_level lvl, const uacpi_char* str) {
  switch (lvl) {
    case UACPI_LOG_ERROR:
      uacpi_logger.error("%s", str);
      break;
    case UACPI_LOG_WARN:
      uacpi_logger.warn("%s", str);
      break;
    case UACPI_LOG_INFO:
      uacpi_logger.info("%s", str);
      break;
    case UACPI_LOG_TRACE:
      uacpi_logger.trace("%s", str);
      break;
    case UACPI_LOG_DEBUG:
      uacpi_logger.debug("%s", str);
      break;
  }
}

uacpi_status uacpi_kernel_get_rsdp(uacpi_phys_addr* out_rsdp_address) {
  if (!out_rsdp_address) uacpi_logger.fatal("out_rsdp_address is NULL!");

  auto addr = reinterpret_cast<std::uintptr_t>(
      kernel::boot::rsdp_request.response->address
  );
  *out_rsdp_address = addr;

  return UACPI_STATUS_OK;
}
}