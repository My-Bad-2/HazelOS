#include "core/insn.hpp"

#include <cstdint>
#include <expected>

#include "compiler.h"
#include "core/logger.hpp"

namespace kernel::x86_64 {
namespace {
log::Logger insn_logger{"INSN"};
}

void InsnDecoder::flag_branches(
    Insn& insn,
    std::uint8_t opcode,
    bool is_two_byte,
    std::uint8_t next_pos
) noexcept {
  if (!is_two_byte) {
    if (opcode == 0xe8 || opcode == 0xe9) {
      insn.is_rel32_branch = true;
      insn.offset_pos      = next_pos;
    } else if (opcode == 0xeb || (opcode >= 0x70 && opcode <= 0x7f)) {
      insn.is_rel8_branch = true;
      insn.offset_pos     = next_pos;
    }
  } else {
    if (opcode >= 0x80 && opcode <= 0x8f) {
      insn.is_rel32_branch = true;
      insn.offset_pos      = next_pos;
    }
  }
}

bool InsnDecoder::needs_modrm(std::uint8_t opcode, bool is_two_byte) noexcept {
  if (!is_two_byte) {
    // Standard ALU ops (ADD, OR, AND, SUB, XOR, CMP)
    // For 0x00 to 0x3f: if the 3rd bit is 0, it requires ModRM
    if (opcode < 0x40) return (opcode & 0x04) == 0;

    if (opcode >= 0x80 && opcode <= 0x8f) return true;  // Maths/MOV with imm
    if (opcode >= 0xc0 && opcode <= 0xc1) return true;  // Shifts
    if (opcode >= 0xc6 && opcode <= 0xc7) return true;  // MOV imm
    if (opcode >= 0xd0 && opcode <= 0xd3) return true;  // Shifts
    if (opcode >= 0xd8 && opcode <= 0xdf) return true;  // FPU escapes
    if (opcode >= 0xf6 && opcode <= 0xf7) return true;  // TEST/NOT/MUL/DIV
    if (opcode >= 0xfe && opcode <= 0xff) return true;  // INC/DEC/CALL mem

    if (opcode == 0x63 || opcode == 0x69 || opcode == 0x6b)
      return true;  // MOVSXD, IMUL

    return false;
  } else {
    if (opcode >= 0x80 && opcode <= 0x8F) return false;  // Jcc rel32
    if (opcode == 0x05 || opcode == 0x34 || opcode == 0x77)
      return false;  // SYSCALL, SYSENTER, EMMS
    if (opcode >= 0xA0 && opcode <= 0xA2) return false;  // PUSH FS/GS, CPUID
    if (opcode >= 0xC8 && opcode <= 0xCF) return false;  // BSWAP

    // GPR extensions, like CMOV, SETcc, Bit tests, all require ModRM
    return true;
  }
}

std::expected<std::uint8_t, DecoderError> InsnDecoder::parse_modrm_sib_disp(
    ByteStream& stream,
    Insn& insn,
    bool has_67
) noexcept {
  auto modrm_res = stream.read();
  if (!modrm_res) return std::unexpected(modrm_res.error());
  const std::uint8_t modrm = *modrm_res;

  const std::uint8_t mod = (modrm >> 6) & 0b11;
  const std::uint8_t rm  = modrm & 0b111;

  if (mod == 0b11) return modrm;  // Register-direct

  // RIP-Relative Addressing check
  if (!has_67 && mod == 0b00 && rm == 0b101) {
    insn.has_rip_relative = true;
    insn.offset_pos       = modrm;

    // disp32 - consume 4 bytes
    for (int i = 0; i < 4; ++i)
      if (!stream.read())
        return std::unexpected(DecoderError::OUT_OF_BOUNDS_READ);

    return modrm;
  }

  bool has_sib          = (rm == 0b100);
  std::uint8_t sib_base = 0;
  if (has_sib) {
    auto sib_res = stream.read();
    if (!sib_res) return std::unexpected(sib_res.error());
    sib_base = *sib_res & 0b111;
  }

  std::uint8_t disp_bytes = 0;

  if (mod == 0b01)
    disp_bytes = 1;  // disp8
  else if (
      (mod == 0b10 || (mod == 0b00 && has_sib && sib_base == 0b101)) ||
      (has_67 && mod == 0b00 && rm == 0b101)
  )
    disp_bytes = 4;  // disp32

  for (int i = 0; i < disp_bytes; ++i)
    if (!stream.read())
      return std::unexpected(DecoderError::OUT_OF_BOUNDS_READ);

  return modrm;
}

std::uint8_t InsnDecoder::get_immediate_size(
    std::uint8_t opcode,
    bool is_two_byte,
    bool has_66,
    bool has_rex_w,
    bool has_modrm,
    std::uint8_t modrm
) noexcept {
  if (!is_two_byte) {
    if (has_modrm && (opcode == 0xf6 || opcode == 0xf7)) {
      std::uint8_t reg = (modrm >> 3) & 0b111;

      // Group 3: TEST has an immediate (reg 0, 1). NOT, NEG, MUL, DIV (reg 2-7)
      // do not.
      if (reg == 0 || reg == 1) return (opcode == 0xf6) ? 1 : (has_66 ? 2 : 4);
      return 0;
    }

    // 8-byte immediates: MOV reg64, imm64
    if (has_rex_w && opcode >= 0xb8 && opcode <= 0xbf) return 8;

    // 1-byte immediates
    if (opcode == 0xeb || (opcode >= 0x70 && opcode <= 0x7f) ||
        opcode == 0x6a || opcode == 0xa8 || opcode == 0xc0 || opcode == 0xc1 ||
        opcode == 0xc6 || opcode == 0x80 || opcode == 0x82 || opcode == 0x83)
      return 1;

    if (opcode < 0x40 && (opcode & 0x07) == 0x04) return 1;  // ALU AL, imm8

    // 2-byte / 4-byte immediates
    if (opcode == 0xe8 || opcode == 0xe9 || opcode == 0x68 || opcode == 0x69 ||
        opcode == 0x81 || opcode == 0xa9 || opcode == 0xc7 ||
        (opcode >= 0xb8 && opcode <= 0xbf))
      return has_66 ? 2 : 4;

    if (opcode < 0x40 && (opcode & 0x07) == 0x05)
      return has_66 ? 2 : 4;  // ALU EAX, imm32
  } else {
    if (opcode >= 0x80 && opcode <= 0x8f) return 4;  // Jcc rel32
  }

  return 0;
}

std::expected<Insn, DecoderError> InsnDecoder::decode(
    std::span<const std::uint8_t> buffer
) noexcept {
  Insn insn{};
  ByteStream stream{buffer};

  bool has_66_prefix = false;  // Operand-Size override
  bool has_67_prefix = false;  // Address-Size override (disables RIP-relative)

  while (true) {
    auto b = stream.peek();
    if (!b) return std::unexpected(b.error());

    if (*b == 0x66) has_66_prefix = true;
    if (*b == 0x67) has_67_prefix = true;

    if (*b == 0x66 || *b == 0x67 || *b == 0xf0 || *b == 0xf2 || *b == 0xf3 ||
        *b == 0x2e || *b == 0x36 || *b == 0x3e || *b == 0x26 || *b == 0x64 ||
        *b == 0x65)
      __maybe_unused auto _ = stream.read();
    else
      break;
  }

  // Parse REX Prefix (0x40 to 0x4f)
  bool has_rex_w = false;  // REX.W promotes operand size to 64-bit
  auto next_byte = stream.peek();
  if (!next_byte) return std::unexpected(next_byte.error());

  if ((*next_byte & 0xf0) == 0x40) {
    has_rex_w             = (*next_byte & 0b1000) != 0;
    __maybe_unused auto _ = stream.read();

    next_byte = stream.peek();
    if (!next_byte) return std::unexpected(next_byte.error());
  }

  // Reject Vector extensions
  if (*next_byte == 0xC4 || *next_byte == 0xC5 || *next_byte == 0x62)
    return std::unexpected(DecoderError::VECTOR_PREFIX_UNSUPPORTED);

  auto opcode_res = stream.read();
  if (!opcode_res) return std::unexpected(opcode_res.error());
  std::uint8_t opcode = *opcode_res;
  bool is_two_byte    = false;

  if (opcode == 0x0f) {
    is_two_byte    = true;
    auto escape_op = stream.read();
    if (!escape_op) return std::unexpected(escape_op.error());
    opcode = *escape_op;

    if (opcode == 0x38 || opcode == 0x3a)
      return std::unexpected(DecoderError::THREE_BYTE_OPCODE_UNSUPPORTED);
  }

  flag_branches(insn, opcode, is_two_byte, stream.position());

  bool has_modrm     = needs_modrm(opcode, is_two_byte);
  uint8_t modrm_byte = 0;

  if (has_modrm) {
    auto parse_res = parse_modrm_sib_disp(stream, insn, has_67_prefix);
    if (!parse_res) return std::unexpected(parse_res.error());
    modrm_byte = *parse_res;
  }

  std::uint8_t imm_size = get_immediate_size(
      opcode,
      is_two_byte,
      has_66_prefix,
      has_rex_w,
      has_modrm,
      modrm_byte
  );

  for (uint8_t i = 0; i < imm_size; ++i)
    if (auto res = stream.read(); !res) return std::unexpected(res.error());

  insn.length = stream.position();
  return insn;
}
}  // namespace kernel::x86_64