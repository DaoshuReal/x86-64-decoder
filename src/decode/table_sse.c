#include "tables.h"

#define M(x) X86DEC_MNEMONIC_##x
#define S(x) X86DEC_SHAPE_##x

static enum x86dec_status_e pick_variant(const X86decSseEntry* row,
    uint16_t fx, const X86decSseVariant** picked)
{
  const X86decSseVariant* selected = &row->base;

  if (fx & X86DEC_FX_F3) {
    selected = &row->variant_f3;
  } else if (fx & X86DEC_FX_F2) {
    selected = &row->variant_f2;
  } else if (fx & X86DEC_FX_66) {
    selected = &row->variant_66;
  }

  if (!selected->mnemonic) {
    return X86DEC_INVALID;
  }

  *picked = selected;
  return X86DEC_OK;
}

static void apply_variant(X86decEntry* out, const X86decSseVariant* picked)
{
  out->mnemonic = picked->mnemonic;
  out->count = picked->count;
  out->shapes[0] = picked->shapes[0];
  out->shapes[1] = picked->shapes[1];
  out->shapes[2] = picked->shapes[2];
  out->shapes[3] = picked->shapes[3];
  out->mem_bits = picked->mem_bits;
}

static int has_row(const X86decSseEntry* row)
{
  return row->base.mnemonic || row->variant_66.mnemonic ||
      row->variant_f3.mnemonic || row->variant_f2.mnemonic;
}

static enum x86dec_status_e resolve_movlhps(X86decEntry* out)
{
  out->mnemonic = M(MOVLHPS);
  out->count = 2;
  out->shapes[0] = S(XMM_REG);
  out->shapes[1] = S(XMM_RM);
  out->shapes[2] = S(NONE);
  out->mem_bits = 0;
  return X86DEC_OK;
}

static enum x86dec_status_e resolve_shift(uint8_t opcode, uint8_t modrm,
    uint16_t fx, X86decEntry* out)
{
  static const uint16_t names_71[8] = {
    0, 0, M(PSRLW), 0, M(PSRAW), 0, M(PSLLW), 0
  };
  static const uint16_t names_72[8] = {
    0, 0, M(PSRLD), 0, M(PSRAD), 0, M(PSLLD), 0
  };
  static const uint16_t names_73[8] = {
    0, 0, M(PSRLQ), M(PSRLDQ), 0, 0, M(PSLLQ), M(PSLLDQ)
  };
  const uint16_t* names = names_71;
  uint8_t reg = (uint8_t)((modrm >> 3) & 7);
  uint16_t mnemonic;
  int use_xmm = (fx & X86DEC_FX_66) != 0;

  if (fx & (X86DEC_FX_F3 | X86DEC_FX_F2)) {
    return X86DEC_INVALID;
  }

  if (opcode == 0x72) {
    names = names_72;
  } else if (opcode == 0x73) {
    names = names_73;
  }

  mnemonic = names[reg];

  if (!mnemonic) {
    return X86DEC_INVALID;
  }

  if (!use_xmm && (mnemonic == M(PSRLDQ) || mnemonic == M(PSLLDQ))) {
    return X86DEC_INVALID;
  }

  out->mnemonic = mnemonic;
  out->count = 2;
  out->shapes[0] = use_xmm ? S(XMM_OR_MEM) : S(MM_OR_MEM);
  out->shapes[1] = S(IMM8);
  out->shapes[2] = S(NONE);
  out->mem_bits = 0;
  return X86DEC_OK;
}

static enum x86dec_status_e resolve_movdq(uint8_t opcode, uint16_t fx,
    X86decEntry* out)
{
  int has_66 = (fx & X86DEC_FX_66) != 0;
  int is_movq = (fx & X86DEC_FX_REXW) != 0;

  if (fx & (X86DEC_FX_F3 | X86DEC_FX_F2)) {
    return X86DEC_INVALID;
  }

  out->count = 2;
  out->mem_bits = 0;
  out->mnemonic = is_movq ? M(MOVQ) : M(MOVD);

  if (opcode == 0x6E) {
    out->shapes[1] = is_movq ? S(GPR_OR_MEM) : S(R32_OR_MEM);
    out->shapes[2] = S(NONE);

    if (has_66) {
      out->shapes[0] = is_movq ? S(XMM64) : S(XMM_REG);
    } else {
      out->shapes[0] = S(MM_REG);
    }
  } else {
    out->shapes[0] = is_movq ? S(GPR_OR_MEM) : S(R32_OR_MEM);
    out->shapes[2] = S(NONE);

    if (has_66) {
      out->shapes[1] = is_movq ? S(XMM64) : S(XMM32);
    } else {
      out->shapes[1] = is_movq ? S(MM_REG) : S(MM32);
    }
  }

  return X86DEC_OK;
}

enum x86dec_status_e x86dec_resolve_sse(uint8_t opcode, uint8_t modrm,
    uint16_t fx, X86decEntry* out)
{
  const X86decSseEntry* row = &x86dec_sse_mov[opcode];
  const X86decSseVariant* picked = 0;
  enum x86dec_status_e status;

  if (opcode == 0x16 && ((modrm >> 6) == 3)) {
    if (fx & (X86DEC_FX_F3 | X86DEC_FX_F2)) {
      return X86DEC_INVALID;
    }

    return resolve_movlhps(out);
  }

  if (opcode >= 0x71 && opcode <= 0x73) {
    return resolve_shift(opcode, modrm, fx, out);
  }

  if (opcode == 0x6E || opcode == 0x7E) {
    return resolve_movdq(opcode, fx, out);
  }

  if (opcode == 0xC4 || opcode == 0xC5) {
    int use_xmm = (fx & X86DEC_FX_66) != 0;
    if (fx & (X86DEC_FX_F3 | X86DEC_FX_F2)) {
      return X86DEC_INVALID;
    }
    if (opcode == 0xC4) {
      out->mnemonic = M(PINSRW);
      out->count = 3;
      out->shapes[0] = use_xmm ? S(XMM_REG) : S(MM_REG);
      out->shapes[1] = S(R32_OR_MEM16);
      out->shapes[2] = S(IMM8);
      out->mem_bits = 0;
      return X86DEC_OK;
    }
    out->mnemonic = M(PEXTRW);
    out->count = 3;
    out->shapes[0] = S(R32_REG);
    out->shapes[1] = use_xmm ? S(XMM_RM) : S(MM_RM);
    out->shapes[2] = S(IMM8);
    out->mem_bits = 0;
    if (((modrm >> 6) & 3) != 3) {
      return X86DEC_INVALID;
    }
    return X86DEC_OK;
  }

  if (!has_row(row)) {
    row = &x86dec_sse_alu[opcode];

    if (!has_row(row)) {
      if (fx & (X86DEC_FX_F3 | X86DEC_FX_F2 | X86DEC_FX_66)) {
        return X86DEC_UNSUPPORTED;
      }

      return X86DEC_INVALID;
    }
  }

  status = pick_variant(row, fx, &picked);

  if (status != X86DEC_OK) {
    return status;
  }

  apply_variant(out, picked);

  switch (out->mnemonic) {
    case M(MOVLPS):
    case M(MOVLPD):
    case M(MOVHPS):
    case M(MOVHPD):
    case M(MOVNTPS):
    case M(MOVNTPD):
    case M(MOVNTDQ):
    case M(MOVNTI):
    case M(MOVNTQ):
    case M(LDDQU):
      if ((modrm >> 6) == 3) {
        return X86DEC_INVALID;
      }
      break;
    default:
      break;
  }

  return X86DEC_OK;
}
