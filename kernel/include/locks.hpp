#ifndef KERNEL_INCLUDE_LOCK_HPP
#define KERNEL_INCLUDE_LOCK_HPP 1

#include <atomic>
#include <cstdint>

namespace kernel {
constexpr std::size_t MAX_NESTING_LEVEL = 4;

struct alignas(std::hardware_destructive_interference_size) MCSNode {
  // Bit 0: Waiting flag (1 = Waiting, 0 = Acquired)
  // Bit 1 - 31: Next Node Index (0 = No Successor)
  std::atomic<std::uint32_t> state[MAX_NESTING_LEVEL]{0};
};

class MCSLock {
 private:
  std::atomic<std::uint32_t> m_tail{0};

 public:
  MCSLock() noexcept                 = default;
  MCSLock(const MCSLock&)            = delete;
  MCSLock& operator=(const MCSLock&) = delete;

  void lock();
  void unlock();
};

class SpinLock {
 private:
  std::atomic<bool> m_locked{false};

 public:
  void lock() noexcept;
  void unlock() noexcept;
  bool try_lock() noexcept;
};
}  // namespace kernel

#endif