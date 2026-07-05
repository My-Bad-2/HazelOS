#include "core/insn.hpp"
#ifndef KERNEL_INCLUDE_CORE_PATCHER_HPP
#define KERNEL_INCLUDE_CORE_PATCHER_HPP 1

#include <concepts>
#include <cstddef>
#include <cstdint>

#include "compiler.h"
#include "cpu/feats.hpp"

namespace kernel::x86_64 {
struct __packed AltEntry {
  std::int32_t instr_offset;
  std::int32_t repl_offset;
  cpu::CpuFeature feature;
  std::uint8_t instr_len;
  std::uint8_t repl_len;

  __nodiscard constexpr std::uint8_t* target_address() const noexcept {
    return reinterpret_cast<std::uint8_t*>(
        reinterpret_cast<std::uintptr_t>(&instr_offset) + instr_offset
    );
  }

  __nodiscard constexpr const std::uint8_t* source_address() const noexcept {
    return reinterpret_cast<const std::uint8_t*>(
        reinterpret_cast<std::uintptr_t>(&repl_offset) + repl_offset
    );
  }
};

template <typename T>
concept ValidFeatureResolver = requires(const T& resolver, cpu::CpuFeature f) {
  { resolver.has_feature(f) } -> std::same_as<bool>;
};

class AlternativePatcher {
 private:
  static void apply_single_patch(const AltEntry& entry) noexcept;
  static void pad_dead_space(std::uint8_t* dest, std::size_t len) noexcept;

  static void toggle_write_protection(bool state) noexcept;
  static void serialize_pipeline(cpu::ProcessorState& state) noexcept;

  static bool fixup_and_audit_instructions(
      std::uint8_t* buffer,
      const std::uint8_t* src,
      const std::uint8_t* dest,
      std::uint8_t len
  ) noexcept;

  static void adjust_rel32(
      std::uint8_t* offset_ptr,
      const std::uint8_t* old_ip,
      const std::uint8_t* new_ip,
      std::uint8_t insn_len,
      std::uint8_t block_len
  ) noexcept;

  static bool adjust_rel8(
      std::uint8_t* offset_ptr,
      const std::uint8_t* old_ip,
      const std::uint8_t* new_ip,
      std::uint8_t insn_len,
      std::uint8_t block_len
  ) noexcept;

  static bool audit_instruction_semantics(const Insn& insn) noexcept;

 public:
  static void apply_patches() noexcept;
};
}  // namespace kernel::x86_64

#endif