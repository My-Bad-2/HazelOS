#include "core/flanterm.hpp"

#include <cstdint>
#include <string_view>

#include "core/boot.hpp"
#include "flanterm_backends/fb.h"
#include "guards.hpp"

namespace kernel {
namespace log {
void FlantermSink::initialize() noexcept {
  const limine_framebuffer* fb =
      boot::framebuffer_request.response->framebuffers[0];
  m_ctx = flanterm_fb_init(
      nullptr,
      nullptr,
      reinterpret_cast<std::uint32_t*>(fb->address),
      fb->width,
      fb->height,
      fb->pitch,
      fb->red_mask_size,
      fb->red_mask_shift,
      fb->green_mask_size,
      fb->green_mask_shift,
      fb->blue_mask_size,
      fb->blue_mask_shift,
      nullptr,
      nullptr,
      nullptr,
      nullptr,
      nullptr,
      nullptr,
      nullptr,
      nullptr,
      0,
      0,
      0,
      0,
      0,
      5,
      FLANTERM_FB_ROTATE_0
  );
}

void FlantermSink::write(std::string_view str) noexcept {
  if (!m_ctx) return;

  const common::LockGuard _(m_lock);
  flanterm_write(m_ctx, str.data(), str.length());
}

void FlantermSink::flush() noexcept {
  const common::LockGuard _(m_lock);
  flanterm_flush(m_ctx);
}
}  // namespace log
}  // namespace kernel