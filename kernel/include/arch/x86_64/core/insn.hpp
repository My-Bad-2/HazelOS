#ifndef KERNEL_INCLUDE_ARCH_CORE_INSN_HPP
#define KERNEL_INCLUDE_ARCH_CORE_INSN_HPP 1

#include <cstdint>
#include <expected>
#include <span>

#include "compiler.h"

namespace kernel::x86_64 {
enum class DecoderError : std::uint8_t {
  OUT_OF_BOUNDS_READ,
  EXCEEDS_15_BYTE_LIMIT,
  VECTOR_PREFIX_UNSUPPORTED,
  THREE_BYTE_OPCODE_UNSUPPORTED,
  INVALID_INSTRUCTION
};

struct Insn {
  std::uint8_t length     = 0;
  bool is_rel32_branch    = false;
  bool is_rel8_branch     = false;
  bool has_rip_relative   = false;
  std::uint8_t offset_pos = 0;
};

class InsnDecoder {
 private:
  class ByteStream {
   private:
    std::span<const std::uint8_t> m_code;
    std::uint8_t m_cursor = 0;

   public:
    explicit ByteStream(std::span<const std::uint8_t> buffer)
        : m_code(buffer) {}

    __nodiscard std::expected<uint8_t, DecoderError> read() noexcept {
      if (m_cursor >= m_code.size())
        return std::unexpected(DecoderError::OUT_OF_BOUNDS_READ);
      if (m_cursor >= 15)
        return std::unexpected(DecoderError::EXCEEDS_15_BYTE_LIMIT);
      return m_code[m_cursor++];
    }

    __nodiscard std::expected<uint8_t, DecoderError> peek() const noexcept {
      if (m_cursor >= m_code.size())
        return std::unexpected(DecoderError::OUT_OF_BOUNDS_READ);

      if (m_cursor >= 15)
        return std::unexpected(DecoderError::EXCEEDS_15_BYTE_LIMIT);

      return m_code[m_cursor];
    }

    __nodiscard uint8_t position() const noexcept {
      return m_cursor;
    }
  };

  static void flag_branches(
      Insn& insn,
      std::uint8_t opcode,
      bool is_two_byte,
      std::uint8_t next_pos
  ) noexcept;

  static bool needs_modrm(std::uint8_t opcode, bool is_two_byte) noexcept;
  static std::expected<std::uint8_t, DecoderError>
  parse_modrm_sib_disp(ByteStream& stream, Insn& insn, bool has_67) noexcept;

  static std::uint8_t get_immediate_size(
      std::uint8_t opcode,
      bool is_two_byte,
      bool has_66,
      bool has_rex_w,
      bool has_modrm,
      std::uint8_t modrm
  ) noexcept;

 public:
  __nodiscard static std::expected<Insn, DecoderError> decode(
      std::span<const std::uint8_t> buffer
  ) noexcept;
};
}  // namespace kernel::x86_64

#endif