#include "tables.h"

#define M(x) X86DEC_MNEMONIC_##x
#define S(x) X86DEC_SHAPE_##x

static int has_0f38_row(const X86decSseEntry* e)
{
  return e->base.mnemonic || e->variant_66.mnemonic || e->variant_f3.mnemonic ||
      e->variant_f2.mnemonic;
}

static enum x86dec_status_e pick_0f38(const X86decSseEntry* e, uint16_t fx,
    X86decEntry* out)
{
  const X86decSseVariant* v = &e->base;

  if (fx & X86DEC_FX_F3) {
    v = &e->variant_f3;
  } else if (fx & X86DEC_FX_F2) {
    v = &e->variant_f2;
  } else if (fx & X86DEC_FX_66) {
    v = &e->variant_66;
  }

  if (!v->mnemonic) {
    return X86DEC_INVALID;
  }

  out->mnemonic = v->mnemonic;
  out->count = v->count;
  out->shapes[0] = v->shapes[0];
  out->shapes[1] = v->shapes[1];
  out->shapes[2] = v->shapes[2];
  out->shapes[3] = v->shapes[3];
  out->mem_bits = v->mem_bits;

  return X86DEC_OK;
}

static void crypto_fill_xmm(X86decEntry* out, uint16_t mnemonic)
{
  out->mnemonic = mnemonic;
  out->count = 2;
  out->shapes[0] = S(XMM_REG);
  out->shapes[1] = S(XMM_OR_MEM);
  out->shapes[2] = S(NONE);
}

static void crypto_fill_xmm_imm(X86decEntry* out, uint16_t mnemonic)
{
  out->mnemonic = mnemonic;
  out->count = 3;
  out->shapes[0] = S(XMM_REG);
  out->shapes[1] = S(XMM_OR_MEM);
  out->shapes[2] = S(IMM8);
}

static enum x86dec_status_e resolve_38(uint8_t opcode, uint8_t modrm,
    uint16_t fx, X86decEntry* out)
{
  int has_66 = (fx & X86DEC_FX_66) != 0;
  int has_simd_prefix = (fx & (X86DEC_FX_F3 | X86DEC_FX_F2)) != 0;

  switch (opcode) {
    case 0xDB:
    case 0xDC:
    case 0xDD:
    case 0xDE:
    case 0xDF:
      if (!has_66 || has_simd_prefix) {
        return X86DEC_INVALID;
      }
      if (opcode == 0xDB) {
        crypto_fill_xmm(out, M(AESIMC));
      } else if (opcode == 0xDC) {
        crypto_fill_xmm(out, M(AESENC));
      } else if (opcode == 0xDD) {
        crypto_fill_xmm(out, M(AESENCLAST));
      } else if (opcode == 0xDE) {
        crypto_fill_xmm(out, M(AESDEC));
      } else {
        crypto_fill_xmm(out, M(AESDECLAST));
      }
      return X86DEC_OK;
    case 0xC8:
    case 0xC9:
    case 0xCA:
    case 0xCB:
    case 0xCC:
    case 0xCD:
      if (has_66 || has_simd_prefix) {
        return X86DEC_INVALID;
      }
      if (opcode == 0xC8) {
        crypto_fill_xmm(out, M(SHA1NEXTE));
      } else if (opcode == 0xC9) {
        crypto_fill_xmm(out, M(SHA1MSG1));
      } else if (opcode == 0xCA) {
        crypto_fill_xmm(out, M(SHA1MSG2));
      } else if (opcode == 0xCB) {
        crypto_fill_xmm(out, M(SHA256RNDS2));
      } else if (opcode == 0xCC) {
        crypto_fill_xmm(out, M(SHA256MSG1));
      } else {
        crypto_fill_xmm(out, M(SHA256MSG2));
      }
      return X86DEC_OK;
    case 0xF0:
    case 0xF1:
      if (has_simd_prefix) {
        if (!(fx & X86DEC_FX_F2) || has_66) {
          return X86DEC_INVALID;
        }
        out->mnemonic = M(CRC32);
        out->count = 2;
        out->shapes[0] = S(GPR_REG);
        out->shapes[1] = opcode == 0xF0 ? S(GPR8_OR_MEM) : S(GPR_OR_MEM);
        out->shapes[2] = S(NONE);
        return X86DEC_OK;
      }
      if (((modrm >> 6) & 3) == 3) {
        return X86DEC_INVALID;
      }
      out->mnemonic = M(MOVBE);
      out->count = 2;
      if (opcode == 0xF0) {
        out->shapes[0] = S(GPR_REG);
        out->shapes[1] = S(MEM_RM);
      } else {
        out->shapes[0] = S(MEM_RM);
        out->shapes[1] = S(GPR_REG);
      }
      out->shapes[2] = S(NONE);
      return X86DEC_OK;
    case 0x00:
    case 0x01:
    case 0x02:
    case 0x03:
    case 0x05:
    case 0x06:
    case 0x07:
    case 0x08:
    case 0x09:
    case 0x0A:
    case 0x0B:
    case 0x1C:
    case 0x1D:
    case 0x1E:
      if (has_simd_prefix) {
        return X86DEC_INVALID;
      }
      if (opcode == 0x00) {
        out->mnemonic = M(PSHUFB);
      } else if (opcode == 0x01) {
        out->mnemonic = M(PHADDW);
      } else if (opcode == 0x02) {
        out->mnemonic = M(PHADDD);
      } else if (opcode == 0x03) {
        out->mnemonic = M(PHADDSW);
      } else if (opcode == 0x05) {
        out->mnemonic = M(PHSUBW);
      } else if (opcode == 0x06) {
        out->mnemonic = M(PHSUBD);
      } else if (opcode == 0x07) {
        out->mnemonic = M(PHSUBSW);
      } else if (opcode == 0x08) {
        out->mnemonic = M(PSIGNB);
      } else if (opcode == 0x09) {
        out->mnemonic = M(PSIGNW);
      } else if (opcode == 0x0A) {
        out->mnemonic = M(PSIGND);
      } else if (opcode == 0x0B) {
        out->mnemonic = M(PMULHRSW);
      } else if (opcode == 0x1C) {
        out->mnemonic = M(PABSB);
      } else if (opcode == 0x1D) {
        out->mnemonic = M(PABSW);
      } else {
        out->mnemonic = M(PABSD);
      }
      out->count = 2;
      if (has_66) {
        out->shapes[0] = S(XMM_REG);
        out->shapes[1] = S(XMM_OR_MEM);
      } else {
        out->shapes[0] = S(MM_REG);
        out->shapes[1] = S(MM_OR_MEM);
      }
      out->shapes[2] = S(NONE);
      return X86DEC_OK;
    case 0xF5:
      if (!has_66 || has_simd_prefix) {
        return X86DEC_INVALID;
      }
      out->mnemonic = (fx & X86DEC_FX_REXW) ? M(WRUSSQ) : M(WRUSSD);
      out->count = 2;
      out->shapes[0] = S(GPR_OR_MEM);
      out->shapes[1] = S(GPR_REG);
      out->shapes[2] = S(NONE);
      return X86DEC_OK;
    case 0xF6:
      if (has_66 || has_simd_prefix) {
        return X86DEC_INVALID;
      }
      out->mnemonic = (fx & X86DEC_FX_REXW) ? M(WRSSQ) : M(WRSSD);
      out->count = 2;
      out->shapes[0] = S(GPR_OR_MEM);
      out->shapes[1] = S(GPR_REG);
      out->shapes[2] = S(NONE);
      return X86DEC_OK;
    default:
      return X86DEC_UNSUPPORTED;
  }
}

static enum x86dec_status_e resolve_3a(uint8_t opcode, uint16_t fx,
    X86decEntry* out)
{
  int has_66 = (fx & X86DEC_FX_66) != 0;
  int has_simd_prefix = (fx & (X86DEC_FX_F3 | X86DEC_FX_F2)) != 0;

  if (opcode == 0xCC) {
    if (has_66 || has_simd_prefix) {
      return X86DEC_INVALID;
    }

    crypto_fill_xmm_imm(out, M(SHA1RNDS4));
    return X86DEC_OK;
  }

  if (opcode == 0x0F) {
    if (has_simd_prefix) {
      return X86DEC_INVALID;
    }

    out->mnemonic = M(PALIGNR);
    out->count = 3;

    if (has_66) {
      out->shapes[0] = S(XMM_REG);
      out->shapes[1] = S(XMM_OR_MEM);
    } else {
      out->shapes[0] = S(MM_REG);
      out->shapes[1] = S(MM_OR_MEM);
    }

    out->shapes[2] = S(IMM8);
    return X86DEC_OK;
  }

  if (!has_66 || has_simd_prefix) {
    if (opcode == 0x44 || opcode == 0xDF) {
      return X86DEC_INVALID;
    }
    return X86DEC_UNSUPPORTED;
  }

  if (opcode == 0x44) {
    crypto_fill_xmm_imm(out, M(PCLMULQDQ));
    return X86DEC_OK;
  }

  if (opcode == 0xDF) {
    crypto_fill_xmm_imm(out, M(AESKEYGENASSIST));
    return X86DEC_OK;
  }

  return X86DEC_UNSUPPORTED;
}

enum x86dec_status_e x86dec_resolve_crypto(uint8_t map, uint8_t opcode,
    uint8_t modrm, uint16_t fx, X86decEntry* out)
{
  enum x86dec_status_e st;

  if (map == 2) {
    const X86decSseEntry* e = &x86dec_0f38[opcode];

    if (has_0f38_row(e)) {
      return pick_0f38(e, fx, out);
    }

    return resolve_38(opcode, modrm, fx, out);
  }

  if (map == 3) {
    const X86decSseEntry* e = &x86dec_0f3a[opcode];

    if (has_0f38_row(e)) {
      st = pick_0f38(e, fx, out);
      if (st != X86DEC_OK) {
        return st;
      }
      if (opcode == 0x16 && (fx & X86DEC_FX_REXW)) {
        out->mnemonic = M(PEXTRQ);
        out->shapes[0] = S(GPR_OR_MEM);
      }
      if (opcode == 0x22 && (fx & X86DEC_FX_REXW)) {
        out->mnemonic = M(PINSRQ);
        out->shapes[1] = S(GPR_OR_MEM);
      }
      return X86DEC_OK;
    }

    return resolve_3a(opcode, fx, out);
  }

  return X86DEC_UNSUPPORTED;
}
