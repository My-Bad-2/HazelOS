#ifndef COMMON_INCLUDE_LOCKS_GUARDS_HPP
#define COMMON_INCLUDE_LOCKS_GUARDS_HPP 1

#include <concepts>
#include <cstddef>
#include <cstdint>

#include "hal/cpu.hpp"

namespace common {
struct adopt_lock_t {
  explicit adopt_lock_t() = default;
};

inline constexpr adopt_lock_t adopt_lock{};

struct defer_lock_t {
  explicit defer_lock_t() = default;
};

inline constexpr defer_lock_t defer_lock{};

template <typename T>
concept BasicLockable = requires(T& a) {
  { a.lock() } -> std::same_as<void>;
  { a.unlock() } -> std::same_as<void>;
};

template <typename T>
concept ExclusiveLockable = requires(T& a) {
  { a.lock() } -> std::same_as<void>;
  { a.unlock() } -> std::same_as<void>;
};

template <typename T>
concept SharedLockable = requires(T& a) {
  { a.lock_shared() } -> std::same_as<void>;
  { a.unlock_shared() } -> std::same_as<void>;
};

template <BasicLockable LockType>
class __nodiscard LockGuard {
 private:
  LockType* m_lock;

 public:
  explicit LockGuard(LockType& lock) noexcept : m_lock(&lock) {
    m_lock->lock();
  }

  LockGuard(LockType& lock, adopt_lock_t) noexcept : m_lock(&lock) {}
  LockGuard(LockType& lock, defer_lock_t) noexcept : m_lock(&lock) {}

  ~LockGuard() {
    if (m_lock) m_lock->unlock();
  }

  void lock() noexcept {
    m_lock->lock();
  }

  void unlock() noexcept {
    m_lock->unlock();
  }

  LockGuard(const LockGuard&)            = delete;
  LockGuard& operator=(const LockGuard&) = delete;

  void* operator new(size_t)   = delete;
  void* operator new[](size_t) = delete;
};

template <BasicLockable LockType>
class __nodiscard InterruptGuard {
 private:
  LockType* m_lock;
  std::uint64_t m_state{0};

 public:
  explicit InterruptGuard(LockType& lock) noexcept : m_lock(&lock) {
    m_state = kernel::hal::cpu::save_interrupt_state();
    kernel::hal::cpu::disable_interrupts();
    m_lock->lock();
  }

  InterruptGuard(
      LockType& lock,
      std::uint64_t adopted_state,
      adopt_lock_t
  ) noexcept
      : m_lock(&lock), m_state(adopted_state) {}

  ~InterruptGuard() {
    if (m_lock) {
      m_lock->unlock();
      kernel::hal::cpu::restore_interrupt_state(m_state);
    }
  }

  InterruptGuard(const InterruptGuard&)            = delete;
  InterruptGuard& operator=(const InterruptGuard&) = delete;

  void* operator new(size_t)   = delete;
  void* operator new[](size_t) = delete;
};

template <SharedLockable LockType>
class __nodiscard ReadGuard {
 private:
  LockType* m_lock;
  bool m_owns_lock;

 public:
  explicit ReadGuard(LockType& lock) noexcept
      : m_lock(&lock), m_owns_lock(true) {
    m_lock->lock_shared();
  }

  ReadGuard(LockType& lock, adopt_lock_t) noexcept
      : m_lock(&lock), m_owns_lock(true) {}

  ReadGuard(LockType& lock, defer_lock_t) noexcept
      : m_lock(&lock), m_owns_lock(false) {}

  ~ReadGuard() {
    if (m_owns_lock) m_lock->unlock_shared();
  }

  void lock() noexcept {
    if (!m_owns_lock) {
      m_lock->lock_shared();
      m_owns_lock = true;
    }
  }

  void unlock() noexcept {
    if (m_owns_lock) {
      m_lock->unlock_shared();
      m_owns_lock = false;
    }
  }

  ReadGuard(const ReadGuard&)            = delete;
  ReadGuard& operator=(const ReadGuard&) = delete;
  void* operator new(size_t)             = delete;
  void* operator new[](size_t)           = delete;
};

template <ExclusiveLockable LockType>
class __nodiscard WriteGuard {
 private:
  LockType* m_lock;
  bool m_owns_lock;

 public:
  explicit WriteGuard(LockType& lock) noexcept
      : m_lock(&lock), m_owns_lock(true) {
    m_lock->lock();
  }

  WriteGuard(LockType& lock, adopt_lock_t) noexcept
      : m_lock(&lock), m_owns_lock(true) {}

  WriteGuard(LockType& lock, defer_lock_t) noexcept
      : m_lock(&lock), m_owns_lock(false) {}

  ~WriteGuard() {
    if (m_owns_lock) m_lock->unlock();
  }

  void lock() noexcept {
    if (!m_owns_lock) {
      m_lock->lock();
      m_owns_lock = true;
    }
  }

  void unlock() noexcept {
    if (m_owns_lock) {
      m_lock->unlock();
      m_owns_lock = false;
    }
  }

  WriteGuard(const WriteGuard&)            = delete;
  WriteGuard& operator=(const WriteGuard&) = delete;
  void* operator new(size_t)               = delete;
  void* operator new[](size_t)             = delete;
};
}  // namespace common

#endif