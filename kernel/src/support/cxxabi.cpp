#include "support/cxxabi.hpp"

#include "compiler.h"

namespace kernel {
namespace support {
using func_ptr_t = void (*)();
extern "C" {
extern const func_ptr_t __preinit_array_start[];
extern const func_ptr_t __preinit_array_end[];
extern const func_ptr_t __init_array_start[];
extern const func_ptr_t __init_array_end[];
extern const func_ptr_t __fini_array_start[];
extern const func_ptr_t __fini_array_end[];
}

namespace {
__always_inline void
call_forward(const func_ptr_t* start, const func_ptr_t* end) {
  while (start < end) (*start++)();
}

__always_inline void
call_reverse(const func_ptr_t* start, const func_ptr_t* end) {
  const func_ptr_t* ptr = end;
  while (ptr > start) (*--ptr)();
}
}  // namespace

void call_global_ctor() {
  call_forward(__preinit_array_start, __preinit_array_end);
  call_forward(__init_array_start, __init_array_end);
}

void call_global_dtor() {
  call_reverse(__fini_array_start, __fini_array_end);
}
}  // namespace support
}  // namespace kernel