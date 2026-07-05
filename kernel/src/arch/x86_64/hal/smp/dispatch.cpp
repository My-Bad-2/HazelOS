#include <atomic>

#include "compiler.h"
#include "cpu/interrupts/common.hpp"
#include "cpu/lapic.hpp"
#include "cpu/lapic/regs.hpp"
#include "cpu/smp.hpp"
#include "hal/smp.hpp"
#include "hal/smp/dispatcher.hpp"
#include "hal/smp/ipi.hpp"

namespace kernel::hal::smp::ipi {
namespace {
using namespace x86_64::cpu;
struct IcrBuilder {
  static lapic::IcrConfig
  build(const Message& msg, lapic::IpiDelivery delivery) {
    auto icr =
        lapic::IcrConfig{}
            .vector(msg.priority == Priority::NMI ? 0 : interrupts::URGENT_IPI)
            .delivery(delivery)
            .dest_mode(lapic::IpiDestMode::PHYSICAL);

    return icr;
  }
};
}  // namespace

void Dispatcher::trigger(
    PerCpuState& target,
    x86_64::cpu::lapic::IcrConfig icr,
    bool is_nmi
) noexcept {
  icr.destination(target.lapic.id());
  __maybe_unused auto _ = get_cpu_state().lapic.send_ipi(icr, is_nmi);
}

void Dispatcher::send(
    PerCpuState& target,
    std::span<const Message> msgs
) noexcept {
  if (msgs.empty()) [[unlikely]]
    return;

  const Priority prio = msgs[0].priority;

  if (prio == Priority::IMMEDIATE) {
    enqueue(target.hot.immediate_queue, msgs);

    if (!target.hot.urgent_ipi_pending
             .exchange(true, std::memory_order_acquire))
      trigger(target, IcrBuilder::build(msgs[0], lapic::IpiDelivery::FIXED));
  } else if (prio == Priority::DEFERRED_TO_IDLE) {
    enqueue(target.cold.idle_queue, msgs);
  } else {
    send_nmi(target, msgs);
  }
}

void Dispatcher::send_nmi(
    PerCpuState& target,
    std::span<const Message> msgs
) noexcept {
  if (msgs.empty()) [[unlikely]]
    return;

  enqueue(target.hot.nmi_queue, msgs);

  if (!target.hot.nmi_pending.exchange(true, std::memory_order_acquire))
    trigger(target, IcrBuilder::build(msgs[0], lapic::IpiDelivery::NMI), true);
}

void Dispatcher::send_self(std::span<const Message> msgs) noexcept {
  if (msgs.empty()) [[unlikely]]
    return;

  PerCpuState& self = get_cpu_state();
  enqueue(self.hot.immediate_queue, msgs);

  if (!self.hot.urgent_ipi_pending.exchange(true, std::memory_order_acquire))
    self.lapic.send_self_ipi(interrupts::URGENT_IPI);
}

void Dispatcher::broadcast(
    std::span<PerCpuState*> all_cpus,
    std::span<const Message> msgs,
    bool include_self
) noexcept {
  if (msgs.empty()) [[unlikely]]
    return;

  PerCpuState& self   = get_cpu_state();
  bool urgent_trigger = false;

  const Priority prio = msgs[0].priority;

  for (std::size_t i = 0; i < all_cpus.size(); ++i) {
    PerCpuState* cpu = all_cpus[i];

    if (i + 1 < all_cpus.size() && all_cpus[i + 1] != nullptr) {
      prefetch(&all_cpus[i + 1]->hot.immediate_queue, 1, 3);
      prefetch(&all_cpus[i + 1]->hot.urgent_ipi_pending, 1, 3);
    }

    if (!cpu) continue;
    if (!include_self && cpu == &self) continue;

    if (prio == Priority::NMI) [[unlikely]] {
      send_nmi(*cpu, msgs);
    } else if (prio == Priority::IMMEDIATE) {
      enqueue(cpu->hot.nmi_queue, msgs);

      if (!cpu->hot.urgent_ipi_pending
               .exchange(true, std::memory_order_acquire))
        urgent_trigger = true;
    } else {
      enqueue(cpu->cold.idle_queue, msgs);
    }
  }

  if (urgent_trigger) {
    __maybe_unused auto _ =
        self.lapic.broadcast_ipi(interrupts::URGENT_IPI, include_self);
  }
}

void Dispatcher::multicast(
    std::span<PerCpuState*> all_cpus,
    std::uint16_t cluster_id,
    std::uint16_t core_mask,
    std::span<const Message> msgs
) noexcept {
  if (msgs.empty()) [[unlikely]]
    return;

  bool requires_hw_trigger = false;
  const Priority prio      = msgs[0].priority;

  for (std::size_t i = 0; i < all_cpus.size(); ++i) {
    PerCpuState* cpu = all_cpus[i];

    if (i + 1 < all_cpus.size() && all_cpus[i + 1] != nullptr) {
      prefetch(&all_cpus[i + 1]->hot.immediate_queue, 1, 3);
      prefetch(&all_cpus[i + 1]->hot.urgent_ipi_pending, 1, 3);
    }

    if (!cpu) continue;

    const lapic::LocalApic& lapic = cpu->lapic;
    if ((lapic.cluster_id() == cluster_id) && (lapic.core_mask() & core_mask)) {
      enqueue(cpu->hot.immediate_queue, msgs);

      if (prio == Priority::IMMEDIATE) {
        enqueue(cpu->hot.immediate_queue, msgs);

        if (!cpu->hot.urgent_ipi_pending
                 .exchange(true, std::memory_order_acquire))
          requires_hw_trigger = true;
      } else if (prio == Priority::DEFERRED_TO_IDLE) {
        enqueue(cpu->cold.idle_queue, msgs);
      } else {
        send_nmi(*cpu, msgs);
      }
    }
  }

  if (requires_hw_trigger)
    __maybe_unused auto _ = get_cpu_state().lapic.broadcast_multicast_ipi(
        cluster_id,
        core_mask,
        interrupts::URGENT_IPI
    );
}
}  // namespace kernel::hal::smp::ipi