#ifndef KERNEL_INCLUDE_HAL_ACPI_TABLES_HPP
#define KERNEL_INCLUDE_HAL_ACPI_TABLES_HPP 1

#include <cstdint>

#include "compiler.h"
#include "hal/acpi/parser.hpp"

namespace kernel {
namespace hal {
namespace acpi {
namespace tables {
struct __packed DescriptionHeader {
  char signature[4];
  std::uint32_t length;
  std::uint8_t revision;
  std::uint8_t checksum;
  char oem_id[6];
  char oem_table_id[8];
  std::uint32_t oem_revision;
  std::uint32_t creator_id;
  std::uint32_t creator_revision;
};
static_assert(
    sizeof(DescriptionHeader) == 36,
    "ACPI SDT Header must be exactly 36 bytes."
);

struct __packed Madt {
  DescriptionHeader header;
  std::uint32_t local_apic_address;
  std::uint32_t flags;

  __nodiscard SubtableView subtables() const noexcept {
    const auto* subtable_start =
        reinterpret_cast<const std::uint8_t*>(this) + sizeof(Madt);
    const std::size_t subtable_length = header.length - sizeof(Madt);
    return SubtableView(subtable_start, subtable_length);
  }
};

enum class MadtType : std::uint8_t {
  LOCAL_APIC                        = 0,
  IO_APIC                           = 1,
  INTERRUPT_SOURCE_OVERRIDE         = 2,
  NMI_SOURCE                        = 3,
  LOCAL_APIC_NMI                    = 4,
  LOCAL_APIC_ADDRESS_OVERRIDE       = 5,
  IO_SAPIC                          = 6,
  LOCAL_SAPIC                       = 7,
  PLATFORM_INTERRUPT_SOURCES        = 8,
  LOCAL_X2APIC                      = 9,
  LOCAL_X2APIC_NMI                  = 10,
  GIC_CPU_INTERFACE                 = 11,
  GIC_DISTRIBUTOR                   = 12,
  GIC_MSI_FRAME                     = 13,
  GIC_REDISTRIBUTOR                 = 14,
  GIC_INTERRUPT_TRANSLATION_SERVICE = 15,
  MULTIPROCESSOR_WAKEUP             = 16,
};

enum class TriggerMode : std::uint8_t {
  LEVEL_TRIGGERED = 0,
  EDGE_TRIGGERED  = 1
};

struct __packed MadtLocalApic {
  SubtableHeader header;
  std::uint8_t acpi_processor_id;
  std::uint8_t apic_id;
  std::uint32_t flags;

  __nodiscard constexpr bool is_enabled() const noexcept {
    return flags & 1;
  }

  __nodiscard constexpr bool is_online_capable() const noexcept {
    return (flags >> 1) & 1;
  }
};

struct __packed MadtIoApic {
  SubtableHeader header;
  std::uint8_t io_apic_id;
  std::uint8_t reserved;
  std::uint32_t io_apic_address;
  std::uint32_t gsi_base;
};

struct __packed MadtInterruptSourceOverride {
  SubtableHeader header;
  std::uint8_t bus;
  std::uint8_t source;
  std::uint32_t gsi;
  std::uint16_t mps_flags;

  __nodiscard constexpr std::uint8_t polarity() const noexcept {
    return mps_flags & 0b11;
  }

  __nodiscard constexpr TriggerMode trigger_mode() const noexcept {
    return static_cast<TriggerMode>((mps_flags >> 2) & 0b11);
  }
};

struct __packed MadtNmiSource {
  SubtableHeader header;
  std::uint16_t mps_flags;
  std::uint32_t gsi;

  __nodiscard constexpr std::uint8_t polarity() const noexcept {
    return mps_flags & 0b11;
  }

  __nodiscard constexpr TriggerMode trigger_mode() const noexcept {
    return static_cast<TriggerMode>((mps_flags >> 2) & 0b11);
  }
};

struct __packed MadtLocalApicNmi {
  SubtableHeader header;
  std::uint8_t acpi_processor_id;
  std::uint16_t mps_flags;
  std::uint8_t local_apic_lint;
};

struct __packed MadtLocalApicOverride {
  SubtableHeader header;
  std::uint16_t reserved;
  std::uint64_t local_apic_address;
};

struct __packed MadtIoSapic {
  SubtableHeader header;
  std::uint8_t io_sapic_id;
  std::uint8_t reserved;
  std::uint32_t gsi_base;
  std::uint64_t io_sapic_address;
};

struct __packed MadtLocalSapic {
  SubtableHeader header;
  std::uint8_t acpi_processor_id;
  std::uint8_t local_sapic_id;
  std::uint8_t local_sapic_eid;
  std::uint8_t reserved[3];
  std::uint32_t flags;
  std::uint32_t acpi_processor_id_val;

  __nodiscard const char* acpi_processor_str() const noexcept {
    return reinterpret_cast<const char*>(this) + sizeof(MadtLocalSapic);
  }
};

enum class InterruptType : std::uint8_t {
  PMI                      = 1,
  INIT                     = 2,
  CORRECTED_PLATFORM_ERROR = 3,
};

struct __packed MadtPlatformInterruptSource {
  SubtableHeader header;
  std::uint16_t mps_flags;
  InterruptType interrupt_type;
  std::uint8_t processor_id;
  std::uint8_t processor_eid;
  std::uint8_t io_sapic_vector;
  std::uint32_t gsi;
  std::uint32_t platform_flags;

  __nodiscard constexpr bool cpei_processor_override() const noexcept {
    return platform_flags & 1;
  }
};

struct __packed MadtLocalX2Apic {
  SubtableHeader header;
  std::uint16_t reserved;
  std::uint32_t x2apic_id;
  std::uint32_t flags;
  std::uint32_t acpi_processor_id;

  __nodiscard constexpr bool is_enabled() const noexcept {
    return flags & 1;
  }

  __nodiscard constexpr bool is_online_capable() const noexcept {
    return (flags >> 1) & 1;
  }
};

struct __packed MadtX2ApicNmi {
  SubtableHeader header;
  std::uint16_t mps_flags;
  std::uint32_t acpi_processor_id;
  std::uint8_t local_x2apic_lint;
  std::uint8_t reserved[3];
};

struct __packed MadtGicC {
  SubtableHeader header;
  std::uint16_t reserved;
  std::uint32_t cpu_interface_number;
  std::uint32_t acpi_processor_id;
  std::uint32_t flags;
  std::uint32_t parking_protocol_version;
  std::uint32_t performance_interrupt_gsiv;
  std::uint64_t parked_address;
  std::uint64_t phys_base_address;
  std::uint64_t gicv;
  std::uint64_t gich;
  std::uint32_t vgic_maintenance_interrupt;
  std::uint64_t gicr_base_address;
  std::uint64_t mpidr;
  std::uint8_t processor_power_efficiency_class;
  std::uint8_t reserved2;
  std::uint16_t spe_overflow_interrupt;

  __nodiscard constexpr bool is_enabled() const noexcept {
    return flags & 1;
  }
  __nodiscard constexpr TriggerMode perf_interrupt_mode() const noexcept {
    return static_cast<TriggerMode>((flags >> 1) & 1);
  }
  __nodiscard constexpr TriggerMode vgic_maintenance_mode() const noexcept {
    return static_cast<TriggerMode>((flags >> 2) & 1);
  }

  __nodiscard constexpr std::uint8_t armv8_aff0() const noexcept {
    return mpidr & 0xFF;
  }

  __nodiscard constexpr std::uint8_t armv8_aff1() const noexcept {
    return (mpidr >> 8) & 0xFF;
  }

  __nodiscard constexpr std::uint8_t armv8_aff2() const noexcept {
    return (mpidr >> 16) & 0xFF;
  }

  __nodiscard constexpr std::uint8_t armv8_aff3() const noexcept {
    return (mpidr >> 32) & 0xFF;
  }
};

struct __packed MadtGicD {
  SubtableHeader header;
  std::uint16_t reserved;
  std::uint32_t gic_id;
  std::uint64_t phys_base_address;
  std::uint32_t system_vector_base;
  std::uint8_t gic_version;
  std::uint8_t reserved2[3];
};

struct __packed MadtGicMsiFrame {
  SubtableHeader header;
  std::uint16_t reserved;
  std::uint32_t gic_msi_frame_id;
  std::uint64_t phys_base_address;
  std::uint32_t flags;
  std::uint16_t spi_count;
  std::uint16_t spi_base;

  __nodiscard constexpr bool spi_select() const noexcept {
    return flags & 1;
  }
};

struct __packed MadtGicR {
  SubtableHeader header;
  std::uint16_t reserved;
  std::uint64_t discovery_range_base_address;
  std::uint32_t discovery_range_length;
};

struct __packed MadtGicIts {
  SubtableHeader header;
  std::uint16_t reserved;
  std::uint32_t gic_its_id;
  std::uint64_t phys_base_address;
  std::uint32_t reserved2;
};

struct __packed MadtMPWakeup {
  SubtableHeader header;
  std::uint16_t mailbox_version;
  std::uint32_t reserved;
  std::uint64_t mailbox_address;
};

struct __packed MadtMPWakeupMailbox {
  std::uint16_t command;  // 0: NoOp; 1: Wakeup
  std::uint16_t reserved;
  std::uint32_t apic_id;
  std::uint64_t wakeup_vector;
  std::uint8_t reserved2[2032];
  std::uint8_t reserved3[2048];
};

static_assert(std::is_standard_layout_v<MadtLocalApic>);
static_assert(std::is_standard_layout_v<MadtMPWakeupMailbox>);
}  // namespace tables
}  // namespace acpi
}  // namespace hal
}  // namespace kernel

#endif