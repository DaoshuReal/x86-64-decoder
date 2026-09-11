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
  X86DEC_SHAPE_MOFFS,
  X86DEC_SHAPE_ST_REG,
  X86DEC_SHAPE_FIXED_ST0,
  X86DEC_SHAPE_FIXED_ST,
  X86DEC_SHAPE_MM_REG,
  X86DEC_SHAPE_MM_OR_MEM,
  X86DEC_SHAPE_XMM_REG,
  X86DEC_SHAPE_XMM_RM,
  X86DEC_SHAPE_XMM_OR_MEM,
  X86DEC_SHAPE_R32_REG,
  X86DEC_SHAPE_R32_OR_MEM,
  X86DEC_SHAPE_MEM16_RM,
  X86DEC_SHAPE_MEM32_RM,
  X86DEC_SHAPE_MEM64_RM,
  X86DEC_SHAPE_MEM80_RM,
  X86DEC_SHAPE_XMM32,
  X86DEC_SHAPE_XMM64,
  X86DEC_SHAPE_MM32,
  X86DEC_SHAPE_IMPLICIT_GPR,
  X86DEC_SHAPE_IMPLICIT_GPR32,
  X86DEC_SHAPE_IMPLICIT_ST0,
  X86DEC_SHAPE_GPR_OR_MEM16,
  X86DEC_SHAPE_IMPLICIT_XMM0,
  X86DEC_SHAPE_MM_RM,
  X86DEC_SHAPE_R32_OR_MEM16,
  X86DEC_SHAPE_YMM_REG,
  X86DEC_SHAPE_YMM_RM,
  X86DEC_SHAPE_YMM_OR_MEM,
  X86DEC_SHAPE_VEX_VVVV,
  X86DEC_SHAPE_VEX_VVVV_GPR,
  X86DEC_SHAPE_YMM32,
  X86DEC_SHAPE_YMM64
};

typedef struct {
  uint16_t mnemonic;
  uint8_t count;
  uint8_t shapes[4];
  uint8_t fixed[4];
  uint8_t flags;
  uint16_t mem_bits;
  uint8_t is_vex;
  uint8_t vex_l;
  uint8_t vex_w;
  uint8_t vex_vvvv;
  uint8_t vex_r;
  uint8_t vex_x;
  uint8_t vex_b;
  uint8_t vex_pp;
  uint8_t vex_map;
  uint8_t vex_opcode;
} X86decEntry;

#define X86DEC_ENTRY_MODRM 0x01u
#define X86DEC_ENTRY_GROUP_SHIFT 1
#define X86DEC_ENTRY_GROUP(g) ((uint8_t)((g) << X86DEC_ENTRY_GROUP_SHIFT))

#define X86DEC_E(mn, c, s0, s1, s2, f0, f1, fl) \
  {(mn), (c), {(s0), (s1), (s2), 0}, {(f0), (f1), 0, 0}, (fl)}

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
  X86DEC_GROUP_0F18,
  X86DEC_GROUP_FPU,
  X86DEC_GROUP_3DNOW,
  X86DEC_GROUP_0F0D,
  X86DEC_GROUP_SSE
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

typedef struct {
  uint16_t mnemonic;
  uint8_t count;
  uint8_t shapes[4];
  uint16_t mem_bits;
} X86decSseVariant;

typedef struct {
  X86decSseVariant base;
  X86decSseVariant variant_66;
  X86decSseVariant variant_f3;
  X86decSseVariant variant_f2;
} X86decSseEntry;

extern const X86decSseEntry x86dec_sse_mov[256];
extern const X86decSseEntry x86dec_sse_alu[256];
extern const X86decSseEntry x86dec_0f38[256];
extern const X86decSseEntry x86dec_0f3a[256];
extern const X86decSseEntry x86dec_vex_0f[256];
extern const X86decSseEntry x86dec_vex_0f38[256];
extern const X86decSseEntry x86dec_vex_0f3a[256];
extern const uint16_t x86dec_3dnow[256];

enum x86dec_status_e x86dec_resolve(uint8_t map, uint8_t opcode,
    uint8_t modrm, uint8_t tail, uint16_t fx, X86decEntry* out);
enum x86dec_status_e x86dec_resolve_sse(uint8_t opcode, uint8_t modrm,
    uint16_t fx, X86decEntry* out);
enum x86dec_status_e x86dec_resolve_crypto(uint8_t map, uint8_t opcode,
    uint8_t modrm, uint16_t fx, X86decEntry* out);
enum x86dec_status_e x86dec_resolve_fpu_low(uint8_t escape, uint8_t modrm,
    X86decEntry* out);
enum x86dec_status_e x86dec_resolve_fpu_high(uint8_t escape, uint8_t modrm,
    X86decEntry* out);
