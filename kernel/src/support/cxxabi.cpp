#include "support/cxxabi.hpp"

#include <cstdint>

#include "compiler.h"
#include "core/logger.hpp"
#include "hal/cpu.hpp"

namespace kernel {
namespace support {
using func_ptr_t = void (*)();
using guard_type = std::uint64_t;

extern "C" {
extern const func_ptr_t __preinit_array_start[];
extern const func_ptr_t __preinit_array_end[];
extern const func_ptr_t __init_array_start[];
extern const func_ptr_t __init_array_end[];
extern const func_ptr_t __fini_array_start[];
extern const func_ptr_t __fini_array_end[];

void* __dso_handle = nullptr;
}

namespace {
log::Logger abi_logger{"C++ABI", log::Level::Error};

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

extern "C" {
int __cxa_guard_acquire(guard_type* obj) {
  // First byte of the guard obj tracks initialization status
  if (*reinterpret_cast<uint8_t*>(obj) == 0) return true;

  return false;
}

void __cxa_guard_release(guard_type* obj) {
  *reinterpret_cast<std::uint8_t*>(obj) = 1;
}

void __cxa_guard_abort(guard_type* obj) {
  static_cast<void>(obj);
}

void __cxa_pure_virtual() {
  abi_logger.fatal("Pure Virtual function called!");
}

int __cxa_atexit(void (*dtor)(void*), void* arg, void* dso) {
  // We don't care about destructing local static variables when the kernel
  // halts.
  static_cast<void>(dtor);
  static_cast<void>(arg);
  static_cast<void>(dso);
  return 0;
}

void __cxa_finalize(void* f) {
  static_cast<void>(f);
}
}
}  // namespace support
}  // namespace kernel