#include "hal/smp/ipi.hpp"

#include <atomic>
#include <cstdint>

#include "cpu/smp.hpp"
#include "hal/cpu.hpp"
#include "hal/smp.hpp"
#include "hal/smp/dispatcher.hpp"
#include "memory/address/virtual.hpp"
#include "memory/address_space.hpp"

namespace kernel::hal::smp {
void PerCpuState::process_ipis() noexcept {
  hot.urgent_ipi_pending.store(false, std::memory_order_release);

  ipi::Message msg;

  while (hot.immediate_queue.pop(msg)) {
    switch (msg.command) {
      case ipi::Command::CLOSURE:
        msg.payload.closure.handler(
            msg.payload.closure.ctx1,
            msg.payload.closure.ctx2,
            reinterpret_cast<void*>(static_cast<std::uintptr_t>(msg.aux_data))
        );
        break;
      case ipi::Command::TLB_SHOOTDOWN: {
        auto& payload = msg.payload.tlb;
        memory::kernel_space->handle_shootdown_ipi(
            memory::VirtAddr{msg.payload.tlb.virt_start}
        );
        if (payload.ack_counter)
          payload.ack_counter->fetch_sub(1, std::memory_order_release);
        break;
      }
      case ipi::Command::TLB_SHOOTDOWN_CTX: {
        auto& payload = msg.payload.tlb;
        memory::kernel_space->handle_shootdown_context_ipi();
        if (payload.ack_counter)
          payload.ack_counter->fetch_sub(1, std::memory_order_release);
        break;
      }
      case ipi::Command::PANIC_SYNC:
      default:
        break;
    }
  }
}

void PerCpuState::process_nmis() noexcept {
  hot.nmi_pending.store(false, std::memory_order_release);

  ipi::Message msg;
  while (hot.nmi_queue.pop(msg))
    if (msg.command == ipi::Command::PANIC_SYNC) cpu::halt(false);
}

void PerCpuState::idle_loop() noexcept {
  while (true) {
    hot.activity.store(CpuActivity::Idle, std::memory_order_release);

    const void* monitor_addr = cold.idle_queue.head_ptr();
    asm volatile("monitor" ::"a"(monitor_addr), "c"(0), "d"(0) : "memory");

    if (!cold.idle_queue.is_empty()) [[unlikely]] {
      hot.activity.store(CpuActivity::Active, std::memory_order_relaxed);
    } else {
      // The cpu wakes if:
      //   1) Any core pushes to the queue.
      //   2) A hardware interrupt arrives
      //   3) An NMI arrives
      cpu::enable_interrupts();
      asm volatile("mwait" ::"a"(0), "c"(0) : "memory");

      cpu::disable_interrupts();
      hot.activity.store(CpuActivity::Active, std::memory_order_relaxed);
    }

    ipi::Message msg;
    if (cold.idle_queue.pop(msg)) [[unlikely]] {
      do {
        if (msg.command == ipi::Command::CLOSURE)
          msg.payload.closure.handler(
              msg.payload.closure.ctx1,
              msg.payload.closure.ctx2,
              reinterpret_cast<void*>(static_cast<std::uintptr_t>(msg.aux_data))
          );
      } while (cold.idle_queue.pop(msg));
    }
  }
}

void PerCpuState::panic_sync() noexcept {
  ipi::Message msg{};
  msg.command  = ipi::Command::PANIC_SYNC;
  msg.priority = ipi::Priority::NMI;

  ipi::Dispatcher::broadcast(get_cpu_topology(), {&msg, 1}, false);
}
}  // namespace kernel::hal::smp