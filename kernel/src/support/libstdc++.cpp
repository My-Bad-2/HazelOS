#include <cstddef>

namespace {
int errno = 0;
}

extern "C" {
void free(void*) {}

int* __llvm_libc_errno() {
  return &errno;
}
}