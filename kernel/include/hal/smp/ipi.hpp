#ifndef KERNEL_INCLUDE_HAL_SMP_IPI_HPP
#define KERNEL_INCLUDE_HAL_SMP_IPI_HPP 1

#include <atomic>
#include <bit>
#include <cstdint>
#include <new>
#include <span>
#include <type_traits>

#include "compiler.h"

namespace kernel::hal::smp {
struct PerCpuState;
}

namespace kernel::hal::smp::ipi {
enum class Command : std::uint8_t {
  CLOSURE,
  TLB_SHOOTDOWN,
  TLB_SHOOTDOWN_CTX,
  PANIC_SYNC
};
enum class Priority : std::uint8_t { IMMEDIATE, DEFERRED_TO_IDLE, NMI };

struct Message final {
  Command command;
  Priority priority;
  std::uint16_t flags;
  std::uint32_t aux_data;

  union {
    struct {
      void (*handler)(void*, void*, void*) noexcept;
      void* ctx1;
      void* ctx2;
    } closure;

    struct {
      std::uintptr_t virt_start;
      std::atomic<std::size_t>* ack_counter;
    } tlb;

    std::uint64_t raw_data[3];
  } payload;
};

static_assert(sizeof(Message) == 32, "IpiMessage must be exactly 32 bytes");
static_assert(
    std::is_trivially_copyable_v<Message> ||
        std::is_default_constructible_v<Message>,
    "IpiMessage must be trivial"
);

template <std::size_t Capacity>
  requires(std::has_single_bit(Capacity))
class IpiQueue final {
 private:
  static constexpr std::size_t Mask = Capacity - 1;

  struct alignas(std::hardware_destructive_interference_size) Slot {
    std::atomic<std::size_t> sequence;
    Message msg;
  };

  std::atomic<std::size_t> m_head{0};
  std::size_t m_tail{0};
  alignas(std::hardware_destructive_interference_size) Slot m_slots[Capacity];

 public:
  constexpr IpiQueue() noexcept {
    for (std::size_t i = 0; i < Capacity; ++i)
      m_slots[i].sequence.store(i, std::memory_order_relaxed);
  }

  __nodiscard bool push(const Message& msg) noexcept {
    Slot* slot       = nullptr;
    std::size_t head = m_head.load(std::memory_order_relaxed);

    while (true) {
      slot            = &m_slots[head & Mask];
      std::size_t seq = slot->sequence.load(std::memory_order_acquire);

      std::intptr_t diff =
          static_cast<std::intptr_t>(seq) - static_cast<std::intptr_t>(head);

      if (diff == 0) [[likely]] {
        if (m_head.compare_exchange_weak(
                head,
                head + 1,
                std::memory_order_relaxed
            ))
          break;
      } else if (diff < 0) [[unlikely]] {
        return false;
      } else {
        head = m_head.load(std::memory_order_relaxed);
      }
    }

    slot->msg = msg;
    slot->sequence.store(head + 1, std::memory_order_release);
    return true;
  }

  __nodiscard bool pop(Message& out_msg) noexcept {
    Slot* slot      = &m_slots[m_tail & Mask];
    std::size_t seq = slot->sequence.load(std::memory_order_acquire);

    if (static_cast<std::intptr_t>(seq) -
            static_cast<std::intptr_t>(m_tail + 1) ==
        0) [[likely]] {
      out_msg = slot->msg;

      slot->sequence.store(m_tail + Capacity, std::memory_order_release);
      m_tail++;
      return true;
    }

    return false;
  }

  __nodiscard const void* head_ptr() const noexcept {
    return &m_head;
  }

  __nodiscard bool is_empty() const noexcept {
    return m_head.load(std::memory_order_relaxed) == m_tail;
  }

  __nodiscard bool push_batch(std::span<const Message> msgs) noexcept {
    const std::size_t count = msgs.size();
    if (count == 0) [[unlikely]]
      return true;
    if (count > Capacity) [[unlikely]]
      return false;

    std::size_t head = m_head.load(std::memory_order_relaxed);

    while (true) {
      Slot* last_slot = &m_slots[(head + count - 1) & Mask];
      std::size_t seq = last_slot->sequence.load(std::memory_order_acquire);

      std::intptr_t diff = static_cast<std::intptr_t>(seq) -
                           static_cast<std::intptr_t>(head + count - 1);

      if (diff == 0) [[likely]] {
        if ((m_head.compare_exchange_weak(
                head,
                head + count,
                std::memory_order_relaxed
            ))) {
          break;
        }
      } else if (diff < 0) [[unlikely]] {
        return false;
      } else {
        head = m_head.load(std::memory_order_relaxed);
      }
    }

    for (std::size_t i = 0; i < count; ++i) {
      std::size_t ticket = head + i;
      Slot* slot         = &m_slots[ticket & Mask];

      __builtin_memcpy(&slot->msg, &msgs[i], sizeof(Message));
      slot->sequence.store(ticket + 1, std::memory_order_release);
    }

    return true;
  }
};
}  // namespace kernel::hal::smp::ipi

#endif