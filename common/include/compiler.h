#ifndef COMMON_COMPILER_H
#define COMMON_COMPILER_H 1

#include <stddef.h>

#ifdef __cplusplus
#define __BEGIN_DECLS extern "C" {
#define __END_DECLS   }
#else
#define __BEGIN_DECLS
#define __END_DECLS
#endif

__BEGIN_DECLS

#ifndef __has_builtin
#define __has_builtin(x) 0
#endif

#ifndef __has_attribute
#define __has_attribute(x) 0
#endif

#define __noreturn            [[noreturn]]
#define __must_check          [[nodiscard]]
#define __maybe_unused        [[maybe_unused]]
#define __fallthrough         [[fallthrough]]
#define __deprecated          [[deprecated]]
#define __deprecated_msg(msg) [[deprecated(msg)]]
#define __nodiscard           [[nodiscard]]

#define __always_inline [[gnu::always_inline]] inline
#define __noinline      [[gnu::noinline]]

#define __packed     [[gnu::packed]]
#define __aligned(x) [[gnu::aligned(x)]]

#define __noreturn     [[noreturn]]
#define __must_check   [[nodiscard]]
#define __maybe_unused [[maybe_unused]]

#define __pure  [[gnu::pure]]
#define __const [[gnu::const]]
#define __weak  [[gnu::weak]]
#define __used  [[gnu::used]]
#define __cold  [[gnu::cold]]
#define __hot   [[gnu::hot]]
#define __naked [[gnu::naked]]

#define __section(sec)  [[gnu::section(#sec)]]
#define __alias(symbol) [[gnu::alias(#symbol)]]

#define __likely   [[gnu::likely]]
#define __unlikely [[gnu::unlikely]]

#define barrier()     __asm__ __volatile__("" : : : "memory")
#define unreachable() __builtin_unreachable()

#define __printf(fmt_idx, arg_idx) [[gnu::format(printf, fmt_idx, arg_idx)]]
#define __scanf(fmt_idx, arg_idx)  [[gnu::format(scanf, fmt_idx, arg_idx)]]
#define __nonnull(...)             [[gnu::nonnull(__VA_ARGS__)]]

#if __has_builtin(__builtin_assume)
#define assume(cond) __builtin_assume(cond)
#else
#define assume(cond)                      \
  do {                                    \
    if (!(cond)) __builtin_unreachable(); \
  } while (0)
#endif

#if __has_builtin(__builtin_expect)
#define likely(x)   __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)
#else
#define likely(x)   (x)
#define unlikely(x) (x)
#endif

#if __has_builtin(__builtin_prefetch)
#define prefetch(addr, ...) __builtin_prefetch(addr, ##__VA_ARGS__)
#else
#define prefetch(addr, ...) \
  do {                      \
  } while (0)
#endif

#ifndef __cplusplus

#define __ctz_generic(val)                                                                                                                                                                \
  _Generic((val), unsigned int: __builtin_ctz, int: __builtin_ctz, unsigned long: __builtin_ctzl, long: __builtin_ctzl, unsigned long long: __builtin_ctzll, long long: __builtin_ctzll)( \
      val                                                                                                                                                                                 \
  )

#define __clz_generic(val)                                                                                                                                                                \
  _Generic((val), unsigned int: __builtin_clz, int: __builtin_clz, unsigned long: __builtin_clzl, long: __builtin_clzl, unsigned long long: __builtin_clzll, long long: __builtin_clzll)( \
      val                                                                                                                                                                                 \
  )

#define __ffs_generic(val)                                                                                                                                                                \
  _Generic((val), unsigned int: __builtin_ffs, int: __builtin_ffs, unsigned long: __builtin_ffsl, long: __builtin_ffsl, unsigned long long: __builtin_ffsll, long long: __builtin_ffsll)( \
      val                                                                                                                                                                                 \
  )

#define __popcount_generic(val)                                                                                                                                                                                         \
  _Generic((val), unsigned int: __builtin_popcount, int: __builtin_popcount, unsigned long: __builtin_popcountl, long: __builtin_popcountl, unsigned long long: __builtin_popcountll, long long: __builtin_popcountll)( \
      val                                                                                                                                                                                                               \
  )

/**
 * ctz - Count Trailing Zeros
 *
 * Returns the number of trailing 0-bits in x, starting at the least significant
 * bit. Returns bit-width of type if x is 0.
 */
#if __has_builtin(__builtin_ctz)
#define ctz(x)                                           \
  ({                                                     \
    __typeof__(x) _x = (x);                              \
    _x == 0 ? (int)(sizeof(_x) * 8) : __ctz_generic(_x); \
  })
#else
#define ctz(x) /* Fallback implementation */
#endif

/**
 * clz - Count Leading Zeros
 *
 * Returns the number of leading 0-bits in x, starting at the most significant
 * bit. Teturns bit-width of type x if 0.
 */
#if __has_builtin(__builtin_clz)
#define clz(x)                                           \
  ({                                                     \
    __typeof__(x) _x = (x);                              \
    _x == 0 ? (int)(sizeof(_x) * 8) : __clz_generic(_x); \
  })
#else
#define clz(x) /* Fallback implementation */
#endif

/**
 * ffs - Find First Set
 *
 * Returns one plus the index of the least significant 1-bit of x, or 0 if x is
 * zero.
 */
#if __has_builtin(__builtin_ffs)
#define ffs(x)              \
  ({                        \
    __typeof__(x) _x = (x); \
    __ffs_generic(_x);      \
  })
#else
#define ffs(x) /* Fallback implementation */
#endif

/**
 * popcount - Population Count (Hamming Weight)
 *
 * Returns the number of 1-bits set in x.
 */
#if __has_builtin(__builtin_popcount) && !defined(popcount)
#define popcount(x)         \
  ({                        \
    __typeof__(x) _x = (x); \
    __popcount_generic(_x); \
  })
#else
#define popcount(x) /* Fallback implementation */
#endif

#endif  // __cplusplus

#if __has_builtin(__builtin_add_overflow)
#define add_overflow(a, b, res) __builtin_add_overflow((a), (b), (res))
#else
#define add_overflow(a, b, res) /* Fallback implementation */
#endif

#if __has_builtin(__builtin_sub_overflow)
#define sub_overflow(a, b, res) __builtin_sub_overflow((a), (b), (res))
#else
#define sub_overflow(a, b, res) /* Fallback implementation */
#endif

#if __has_builtin(__builtin_mul_overflow)
#define mul_overflow(a, b, res) __builtin_mul_overflow((a), (b), (res))
#else
#define mul_overflow(a, b, res) /* Fallback implementation */
#endif

#if defined(__SIZEOF_INT128__)
typedef __int128 int128_t;
typedef unsigned __int128 uint128_t;
#endif

typedef ptrdiff_t ssize_t;

__END_DECLS

#endif  // COMMON_COMPILER_H