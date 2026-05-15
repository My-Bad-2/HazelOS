#include <cstddef>
extern "C" {
void free(void*) {}

std::size_t strlen(const char* str) {
  std::size_t i = 0;
  while (str[i] != '\0') {
    i++;
  }
  return i;
}
}