#pragma once

#include <stdint.h>

#include "core/types.h"
#include "core/mnemonic.h"

enum x86dec_shape_e {
  X86DEC_SHAPE_NONE = 0,
  X86DEC_SHAPE_GPR_REG,
  X86DEC_SHAPE_GPR_RM,
  X86DEC_SHAPE_MEM_RM,
  X86DEC_SHAPE_GPR_OR_MEM,
  X86DEC_SHAPE_GPR8_REG,
  X86DEC_SHAPE_GPR8_RM,
  X86DEC_SHAPE_MEM8_RM,
  X86DEC_SHAPE_GPR8_OR_MEM,
  X86DEC_SHAPE_GPR16_REG,
  X86DEC_SHAPE_GPR16_OR_MEM,
  X86DEC_SHAPE_REG_OPCODE,
  X86DEC_SHAPE_REG8_OPCODE,
  X86DEC_SHAPE_FIXED_GPR,
  X86DEC_SHAPE_FIXED_GPR8,
  X86DEC_SHAPE_FIXED_GPR16,
  X86DEC_SHAPE_FIXED_SEG,
  X86DEC_SHAPE_SEG_REG,
  X86DEC_SHAPE_CREG_REG,
  X86DEC_SHAPE_DREG_REG,
  X86DEC_SHAPE_IMM8,
  X86DEC_SHAPE_IMM16,
  X86DEC_SHAPE_IMM_V,
  X86DEC_SHAPE_IMM_V64,
  X86DEC_SHAPE_IMM_VS,
  X86DEC_SHAPE_IMM_ONE,
  X86DEC_SHAPE_REL8,
  X86DEC_SHAPE_REL_V,
  X86DEC_SHAPE_MOFFS
};

typedef struct {
  uint16_t mnemonic;
  uint8_t count;
  uint8_t shapes[3];
  uint8_t fixed[3];
  uint8_t flags;
} X86decEntry;

#define X86DEC_ENTRY_MODRM 0x01u
#define X86DEC_ENTRY_GROUP_SHIFT 1
#define X86DEC_ENTRY_GROUP(g) ((uint8_t)((g) << X86DEC_ENTRY_GROUP_SHIFT))

#define X86DEC_E(mn, c, s0, s1, s2, f0, f1, fl) \
  {(mn), (c), {(s0), (s1), (s2)}, {(f0), (f1)}, (fl)}

enum x86dec_group_e {
  X86DEC_GROUP_NONE = 0,
  X86DEC_GROUP_1,
  X86DEC_GROUP_2,
  X86DEC_GROUP_3B,
  X86DEC_GROUP_3V,
  X86DEC_GROUP_4,
  X86DEC_GROUP_5,
  X86DEC_GROUP_11B,
  X86DEC_GROUP_11V,
  X86DEC_GROUP_6,
  X86DEC_GROUP_7,
  X86DEC_GROUP_8,
  X86DEC_GROUP_9,
  X86DEC_GROUP_15,
  X86DEC_GROUP_0F18
};

enum x86dec_fx_e {
  X86DEC_FX_64 = 1u << 0,
  X86DEC_FX_EOSZ_SHIFT = 1,
  X86DEC_FX_EASZ_SHIFT = 3,
  X86DEC_FX_F3 = 1u << 5,
  X86DEC_FX_F2 = 1u << 6,
  X86DEC_FX_66 = 1u << 7,
  X86DEC_FX_REX = 1u << 10,
  X86DEC_FX_REXW = 1u << 8,
  X86DEC_FX_REXB = 1u << 9
};

extern const X86decEntry x86dec_map0[256];
extern const X86decEntry x86dec_map1[256];

enum x86dec_status_e x86dec_resolve(uint8_t map, uint8_t opcode,
    uint8_t modrm, uint16_t fx, X86decEntry* out);
