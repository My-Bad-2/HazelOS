#include "core/patcher.hpp"

#include <cstddef>
#include <cstdint>
#include <string.h>

#include "core/insn.hpp"
#include "core/log_sink.hpp"
#include "core/logger.hpp"
#include "cpu/feats.hpp"
#include "cpu/registers.hpp"

namespace kernel::x86_64 {
namespace {
log::Logger patch_logger{"PATCHER", log::Level::Debug};
}

extern "C" {
extern std::uint8_t __alt_instructions_start[];
extern std::uint8_t __alt_instructions_end[];
}

void AlternativePatcher::apply_patches() noexcept {
  const std::ptrdiff_t diff = __alt_instructions_end - __alt_instructions_start;
  const std::size_t bytes   = static_cast<std::uint64_t>(diff);
  const std::size_t count   = bytes / sizeof(AltEntry);

  std::span<const AltEntry> alternatives{
      reinterpret_cast<const AltEntry*>(__alt_instructions_start),
      count
  };

  cpu::ProcessorState& state = cpu::get_current_state();

  toggle_write_protection(false);

  for (const auto& entry : alternatives)
    if (state.has_feature(entry.feature)) apply_single_patch(entry);

  toggle_write_protection(true);
  serialize_pipeline(state);
}

bool AlternativePatcher::fixup_and_audit_instructions(
    std::uint8_t* buffer,
    const std::uint8_t* src,
    const std::uint8_t* dest,
    std::uint8_t len
) noexcept {
  std::uint8_t cursor = 0;

  while (cursor < len) {
    std::span<const std::uint8_t> remaining_code{
        buffer + cursor,
        static_cast<std::size_t>(len - cursor)
    };

    auto decode_res = InsnDecoder::decode(remaining_code);
    if (!decode_res) return false;

    x86_64::Insn insn = decode_res.value();
    if (insn.length == 0 || cursor + insn.length > len) return false;

    if (!audit_instruction_semantics(insn)) return false;

    if (insn.is_rel32_branch || insn.has_rip_relative)
      adjust_rel32(
          &buffer[cursor + insn.offset_pos],
          src + cursor,
          dest + cursor,
          insn.length,
          len
      );
    else if (insn.is_rel8_branch)
      if (!adjust_rel8(
              &buffer[cursor + insn.offset_pos],
              src + cursor,
              dest + cursor,
              insn.length,
              len
          ))
        return false;  // Shoft jump overflowed

    cursor += insn.length;
  }

  return true;
}

void AlternativePatcher::adjust_rel32(
    std::uint8_t* offset_ptr,
    const std::uint8_t* old_ip,
    const std::uint8_t* new_ip,
    std::uint8_t insn_len,
    std::uint8_t block_len
) noexcept {
  std::int32_t old_offset;
  memcpy(&old_offset, offset_ptr, sizeof(old_offset));

  const std::uint8_t* target = old_ip + insn_len + old_offset;
  if (target >= old_ip && target < (old_ip + block_len)) return;

  std::int32_t new_offset =
      static_cast<std::int32_t>(target - (new_ip + insn_len));
  memcpy(offset_ptr, &new_offset, sizeof(new_offset));
}

bool AlternativePatcher::adjust_rel8(
    std::uint8_t* offset_ptr,
    const std::uint8_t* old_ip,
    const std::uint8_t* new_ip,
    std::uint8_t insn_len,
    std::uint8_t block_len
) noexcept {
  std::int8_t old_offset     = static_cast<std::int8_t>(*offset_ptr);
  const std::uint8_t* target = old_ip + insn_len + old_offset;

  if (target >= old_ip && target < (old_ip + block_len)) return true;

  ptrdiff_t new_distance = target - (new_ip + insn_len);
  if (new_distance > 127 || new_distance < -128) return false;

  *offset_ptr =
      static_cast<std::uint8_t>(static_cast<std::int8_t>(new_distance));
  return true;
}

bool AlternativePatcher::audit_instruction_semantics(
    const Insn& insn
) noexcept {
  if (insn.is_locked) {
    // If ModRm 'mod' bits are 0b11, it targets a register. That's a #UD
    if (!insn.has_modrm || ((insn.modrm >> 6) & 0b11) == 0b11) return false;

    // Only a strict no. of math/logic opcodes can be locked.
    if (!insn.is_two_byte) {
      const std::uint8_t op = insn.opcode;

      // ADD, OR, ADC, SBB, AND, SUB, XOR
      const bool valid_math = (op >= 0x00 && op <= 0x35);
      const bool valid_grp  = (op >= 0xfe);                // INC, DEC, NOT, NEG
      const bool valid_xchg = (op == 0x86 || op == 0x87);  // XCHG

      if (!valid_math && !valid_grp && !valid_xchg) return false;
    } else {
      const std::uint8_t op      = insn.opcode;
      const bool valid_bts       = (op >= 0xab && op <= 0xbb);  // BTS, BTR, BTC
      const bool valid_cmpxchg8b = (op == 0xc7);
      const bool valid_xadd =
          (op == 0xb0 || op == 0xb1 || op == 0xc0 ||
           op == 0xc1);  // CMPXCHG, XADD

      if (!valid_bts && !valid_xadd && !valid_cmpxchg8b) return false;
    }
  }

  if (insn.has_fs_override || insn.has_gs_override)
    if (insn.is_rel8_branch || insn.is_rel32_branch) return false;

  return true;
}

void AlternativePatcher::apply_single_patch(const AltEntry& entry) noexcept {
  if (entry.repl_len > entry.instr_len)
    patch_logger.fatal("Alternative replacement is larger than original code!");

  std::uint8_t* dest      = entry.target_address();
  const std::uint8_t* src = entry.source_address();

  std::uint8_t buffer[128];
  if (entry.repl_len > sizeof(buffer))
    patch_logger.fatal("Alternative replacement exceeds internal buffer size!");

  memcpy(buffer, src, entry.repl_len);

  if (!fixup_and_audit_instructions(buffer, src, dest, entry.repl_len))
    patch_logger.fatal("Decoder failed during alternative patch fixups.");

  memcpy(dest, buffer, entry.repl_len);

  const std::size_t padding_needed = entry.instr_len - entry.repl_len;
  if (padding_needed > 0) pad_dead_space(dest + entry.repl_len, padding_needed);
}

void AlternativePatcher::pad_dead_space(
    std::uint8_t* dest,
    std::size_t len
) noexcept {
  static constexpr std::uint8_t nops[10][9] = {
      {},
      {0x90},
      {0x66, 0x90},
      {0x0f, 0x1f, 0x00},
      {0x0f, 0x1f, 0x40, 0x00},
      {0x0f, 0x1f, 0x44, 0x00, 0x00},
      {0x66, 0x0f, 0x1f, 0x44, 0x00, 0x00},
      {0x0f, 0x1f, 0x80, 0x00, 0x00, 0x00, 0x00},
      {0x0f, 0x1f, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00},
      {0x66, 0x0f, 0x1f, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00}
  };

  if (len > 6) {
    dest[0] = 0xeb;  // jmp rel8 opcode;
    dest[1] = static_cast<std::uint8_t>(len - 2);
    memset(dest + 2, 0xcc, len - 2);
  } else {
    while (len > 0) {
      const std::size_t step = std::min(len, 9ul);

      memcpy(dest, nops[step], step);
      dest += step;
      len -= step;
    }
  }
}

void AlternativePatcher::toggle_write_protection(bool enabled) noexcept {
  auto cr0               = cpu::read<cpu::CR0>();
  cr0.bits.write_protect = enabled;
  cpu::write(cr0);
}

void AlternativePatcher::serialize_pipeline(
    cpu::ProcessorState& state
) noexcept {
  if (state.has_feature(cpu::CpuFeature::SERIALIZE)) {
    asm volatile("serialize" ::: "memory");
  } else {
    int a, b, c, d;
    asm volatile("cpuid"
                 : "=a"(a), "=b"(b), "=c"(c), "=d"(d)
                 : "0"(0)
                 : "memory");
  }
}
}  // namespace kernel::x86_64