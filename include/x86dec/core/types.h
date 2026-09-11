#pragma once

#include <stddef.h>
#include <stdint.h>

#define X86DEC_MAX_INSN_LENGTH 15
#define X86DEC_MAX_OPERANDS 10

#if defined(__clang__) || defined(__GNUC__)
#define X86DEC_LIKELY(x) __builtin_expect(!!(x), 1)
#define X86DEC_UNLIKELY(x) __builtin_expect(!!(x), 0)
#else
#define X86DEC_LIKELY(x) (x)
#define X86DEC_UNLIKELY(x) (x)
#endif

enum x86dec_status_e {
  X86DEC_OK = 0,
  X86DEC_NEED_MORE = 1,
  X86DEC_INVALID = 2,
  X86DEC_UNSUPPORTED = 3,
  X86DEC_BAD_ARG = 4
};

enum x86dec_machine_mode_e {
  X86DEC_MODE_LONG_64 = 0,
  X86DEC_MODE_COMPAT_32 = 1,
  X86DEC_MODE_COMPAT_16 = 2,
  X86DEC_MODE_LEGACY_32 = 3,
  X86DEC_MODE_LEGACY_16 = 4,
  X86DEC_MODE_REAL_16 = 5
};

enum x86dec_stack_width_e {
  X86DEC_STACK_16 = 16,
  X86DEC_STACK_32 = 32,
  X86DEC_STACK_64 = 64
};
