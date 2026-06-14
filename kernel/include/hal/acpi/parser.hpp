#include <utility>
#ifndef KERNEL_INCLUDE_HAL_ACPI_PARSER_HPP
#define KERNEL_INCLUDE_HAL_ACPI_PARSER_HPP 1

#include <cstdint>
#include <expected>
#include <iterator>
#include <type_traits>

#include "compiler.h"
#include "uacpi/tables.h"

namespace kernel {
namespace hal {
namespace acpi {
template <typename T>
concept AcpiTable = std::is_standard_layout_v<T> &&
                    std::is_trivially_default_constructible_v<T> &&
                    std::is_trivially_copyable_v<T>;

template <AcpiTable T>
class TableAccessor {
 private:
  uacpi_table m_tbl{};

 public:
  explicit TableAccessor(uacpi_table tbl) noexcept : m_tbl(tbl) {}

  ~TableAccessor() {
    if (m_tbl.ptr) uacpi_table_unref(&m_tbl);
  }

  TableAccessor(const TableAccessor&)            = delete;
  TableAccessor& operator=(const TableAccessor&) = delete;

  TableAccessor(TableAccessor&& other) noexcept
      : m_tbl(std::exchange(other.m_tbl, {})) {}

  TableAccessor& operator=(TableAccessor&& other) noexcept {
    if (this != &other) {
      if (m_tbl.ptr) uacpi_table_unref(&m_tbl);
      m_tbl = std::exchange(other.m_tbl, {});
    }

    return *this;
  }

  __nodiscard const T* operator->() const noexcept {
    return static_cast<const T*>(m_tbl.ptr);
  }

  __nodiscard const T& operator*() const noexcept {
    return *static_cast<const T*>(m_tbl.ptr);
  }

  __nodiscard const T* get() const noexcept {
    return static_cast<const T*>(m_tbl.ptr);
  }
};

template <AcpiTable T>
__nodiscard std::expected<TableAccessor<T>, uacpi_status> get_table(
    const char (&signature)[5]
) {
  uacpi_table tbl{};

  if (auto status = uacpi_table_find_by_signature(signature, &tbl);
      status != UACPI_STATUS_OK)
    return std::unexpected(status);

  return TableAccessor<T>(tbl);
}

struct SubtableHeader {
  std::uint8_t type;
  std::uint8_t length;
};

class SubtableView {
 private:
  const std::uint8_t* m_begin;
  const std::uint8_t* m_end;

 public:
  SubtableView(const void* start, std::size_t total_length) noexcept
      : m_begin(static_cast<const std::uint8_t*>(start)),
        m_end(m_begin + total_length) {}

  class Iterator {
   private:
    const std::uint8_t* m_ptr;

   public:
    using iterator_category = std::forward_iterator_tag;
    using value_type        = SubtableHeader;
    using difference_type   = std::ptrdiff_t;
    using pointer           = const SubtableHeader*;
    using reference         = const SubtableHeader&;

    explicit Iterator(const std::uint8_t* p) : m_ptr(p) {}

    reference operator*() const {
      return *reinterpret_cast<pointer>(m_ptr);
    }

    pointer operator->() const {
      return reinterpret_cast<pointer>(m_ptr);
    }

    Iterator& operator++() {
      if (m_ptr) {
        const std::uint8_t len = (*this)->length;
        m_ptr += (len == 0) ? 1 : len;
      }

      return *this;
    }

    Iterator operator++(int) {
      Iterator tmp = *this;
      ++(*this);
      return tmp;
    }

    bool operator==(const Iterator& other) const {
      return m_ptr >= other.m_ptr;
    }
  };

  __nodiscard Iterator begin() const {
    return Iterator{m_begin};
  }

  __nodiscard Iterator end() const {
    return Iterator{m_end};
  }
};
}  // namespace acpi
}  // namespace hal
}  // namespace kernel

#endif