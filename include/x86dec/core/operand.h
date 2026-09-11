#pragma once

#include <stdbool.h>
#include <stdint.h>

#include "core/register.h"

enum x86dec_operand_type_e {
  X86DEC_OPERAND_NONE = 0,
  X86DEC_OPERAND_REG,
  X86DEC_OPERAND_MEM,
  X86DEC_OPERAND_IMM
};

enum x86dec_operand_visibility_e {
  X86DEC_OPERAND_VISIBLE = 0,
  X86DEC_OPERAND_IMPLICIT,
  X86DEC_OPERAND_HIDDEN
};

typedef struct {
  enum x86dec_register_e base;
  enum x86dec_register_e index;
  uint8_t scale;
  int64_t disp;
  bool has_disp;
  enum x86dec_register_e segment;
} X86decMem;

typedef struct {
  uint8_t id;
  enum x86dec_operand_visibility_e visibility;
  enum x86dec_operand_type_e type;
  uint16_t size;
  union {
    enum x86dec_register_e reg;
    X86decMem mem;
    struct {
      uint64_t value;
      bool is_relative;
    } imm;
  };
} X86decOperand;
