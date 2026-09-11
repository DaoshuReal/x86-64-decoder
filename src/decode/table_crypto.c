#include "tables.h"

#define M(x) X86DEC_MNEMONIC_##x
#define S(x) X86DEC_SHAPE_##x

static void fill_xmm(X86decEntry* out, uint16_t mnemonic)
{
  out->mnemonic = mnemonic;
  out->count = 2;
  out->shapes[0] = S(XMM_REG);
  out->shapes[1] = S(XMM_OR_MEM);
  out->shapes[2] = S(NONE);
}

static void fill_xmm_imm(X86decEntry* out, uint16_t mnemonic)
{
  out->mnemonic = mnemonic;
  out->count = 3;
  out->shapes[0] = S(XMM_REG);
  out->shapes[1] = S(XMM_OR_MEM);
  out->shapes[2] = S(IMM8);
}

static enum x86dec_status_e resolve_38(uint8_t opcode, uint16_t fx,
    X86decEntry* out)
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
        fill_xmm(out, M(AESIMC));
      } else if (opcode == 0xDC) {
        fill_xmm(out, M(AESENC));
      } else if (opcode == 0xDD) {
        fill_xmm(out, M(AESENCLAST));
      } else if (opcode == 0xDE) {
        fill_xmm(out, M(AESDEC));
      } else {
        fill_xmm(out, M(AESDECLAST));
      }
      return X86DEC_OK;
    case 0xC8:
    case 0xC9:
    case 0xCA:
    case 0xCC:
    case 0xCD:
    case 0xCE:
      if (has_66 || has_simd_prefix) {
        return X86DEC_INVALID;
      }
      if (opcode == 0xC8) {
        fill_xmm(out, M(SHA1NEXTE));
      } else if (opcode == 0xC9) {
        fill_xmm(out, M(SHA1MSG1));
      } else if (opcode == 0xCA) {
        fill_xmm(out, M(SHA1MSG2));
      } else if (opcode == 0xCC) {
        fill_xmm(out, M(SHA256RNDS2));
      } else if (opcode == 0xCD) {
        fill_xmm(out, M(SHA256MSG1));
      } else {
        fill_xmm(out, M(SHA256MSG2));
      }
      return X86DEC_OK;
    case 0xCB:
      if (has_66 || has_simd_prefix) {
        return X86DEC_INVALID;
      }
      fill_xmm_imm(out, M(SHA1RNDS4));
      return X86DEC_OK;
    case 0xF0:
    case 0xF1:
      if (!(fx & X86DEC_FX_F2) || has_66) {
        return X86DEC_INVALID;
      }
      out->mnemonic = M(CRC32);
      out->count = 2;
      out->shapes[0] = S(GPR_REG);
      out->shapes[1] = opcode == 0xF0 ? S(GPR8_OR_MEM) : S(GPR_OR_MEM);
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

  if (!has_66 || has_simd_prefix) {
    if (opcode == 0x44 || opcode == 0xDF) {
      return X86DEC_INVALID;
    }
    return X86DEC_UNSUPPORTED;
  }

  if (opcode == 0x44) {
    fill_xmm_imm(out, M(PCLMULQDQ));
    return X86DEC_OK;
  }

  if (opcode == 0xDF) {
    fill_xmm_imm(out, M(AESKEYGENASSIST));
    return X86DEC_OK;
  }

  return X86DEC_UNSUPPORTED;
}

enum x86dec_status_e x86dec_resolve_crypto(uint8_t map, uint8_t opcode,
    uint8_t modrm, uint16_t fx, X86decEntry* out)
{
  (void)modrm;

  if (map == 2) {
    return resolve_38(opcode, fx, out);
  }

  if (map == 3) {
    return resolve_3a(opcode, fx, out);
  }

  return X86DEC_UNSUPPORTED;
}
