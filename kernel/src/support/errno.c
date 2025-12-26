#include <errno.h>

static int err = 0;

int* __llvm_libc_errno(void) {
    return &err;
}