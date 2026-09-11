#include "tables.h"

#define M(x) X86DEC_MNEMONIC_##x
#define S(x) X86DEC_SHAPE_##x

static void fill_mem(X86decEntry* out, uint16_t mnemonic, uint8_t shape)
{
  out->mnemonic = mnemonic;
  out->count = 1;
  out->shapes[0] = shape;
  out->shapes[1] = S(NONE);
  out->shapes[2] = S(NONE);
}

static void fill_none(X86decEntry* out, uint16_t mnemonic)
{
  out->mnemonic = mnemonic;
  out->count = 0;
  out->shapes[0] = S(NONE);
  out->shapes[1] = S(NONE);
  out->shapes[2] = S(NONE);
}

static void fill_pair(X86decEntry* out, uint16_t mnemonic)
{
  out->mnemonic = mnemonic;
  out->count = 2;
  out->shapes[0] = S(FIXED_ST0);
  out->shapes[1] = S(ST_REG);
  out->shapes[2] = S(NONE);
}

static void fill_st(X86decEntry* out, uint16_t mnemonic)
{
  out->mnemonic = mnemonic;
  out->count = 1;
  out->shapes[0] = S(ST_REG);
  out->shapes[1] = S(NONE);
  out->shapes[2] = S(NONE);
}

static void fill_fixed_st(X86decEntry* out, uint16_t mnemonic, uint8_t index)
{
  out->mnemonic = mnemonic;
  out->count = 1;
  out->shapes[0] = S(FIXED_ST);
  out->shapes[1] = S(NONE);
  out->shapes[2] = S(NONE);
  out->fixed[0] = index;
}

static enum x86dec_status_e resolve_d8(uint8_t modrm, X86decEntry* out)
{
  static const uint16_t arith[8] = {
    M(FADD), M(FMUL), M(FCOM), M(FCOMP), M(FSUB), M(FSUBR), M(FDIV), M(FDIVR)
  };
  uint8_t reg = (uint8_t)((modrm >> 3) & 7);

  if ((modrm >> 6) != 3) {
    fill_mem(out, arith[reg], S(MEM32_RM));
    return X86DEC_OK;
  }

  if (reg == 2 || reg == 3) {
    fill_st(out, arith[reg]);
    return X86DEC_OK;
  }

  fill_pair(out, arith[reg]);
  return X86DEC_OK;
}

static enum x86dec_status_e resolve_d9(uint8_t modrm, X86decEntry* out)
{
  static const uint16_t mem[8] = {
    M(FLD), 0, M(FST), M(FSTP), M(FLDENV), M(FLDCW), M(FNSTENV), M(FNSTCW)
  };
  static const uint8_t shapes[8] = {
    S(MEM32_RM), 0, S(MEM32_RM), S(MEM32_RM),
    S(MEM_RM), S(MEM16_RM), S(MEM_RM), S(MEM16_RM)
  };
  uint8_t reg = (uint8_t)((modrm >> 3) & 7);

  if ((modrm >> 6) != 3) {
    if (!mem[reg]) {
      return X86DEC_INVALID;
    }

    fill_mem(out, mem[reg], shapes[reg]);
    return X86DEC_OK;
  }

  if (modrm >= 0xC0 && modrm <= 0xC7) {
    fill_st(out, M(FLD));
    return X86DEC_OK;
  }

  if (modrm >= 0xC8 && modrm <= 0xCF) {
    fill_st(out, M(FXCH));
    return X86DEC_OK;
  }

  if (modrm >= 0xD8 && modrm <= 0xDF) {
    fill_fixed_st(out, M(FSTP), 1);
    return X86DEC_OK;
  }

  switch (modrm) {
    case 0xD0:
      fill_none(out, M(FNOP));
      return X86DEC_OK;
    case 0xE0:
      fill_none(out, M(FCHS));
      return X86DEC_OK;
    case 0xE1:
      fill_none(out, M(FABS));
      return X86DEC_OK;
    case 0xE4:
      fill_none(out, M(FTST));
      return X86DEC_OK;
    case 0xE5:
      fill_none(out, M(FXAM));
      return X86DEC_OK;
    case 0xE8:
      fill_none(out, M(FLD1));
      return X86DEC_OK;
    case 0xE9:
      fill_none(out, M(FLDL2T));
      return X86DEC_OK;
    case 0xEA:
      fill_none(out, M(FLDL2E));
      return X86DEC_OK;
    case 0xEB:
      fill_none(out, M(FLDPI));
      return X86DEC_OK;
    case 0xEC:
      fill_none(out, M(FLDLG2));
      return X86DEC_OK;
    case 0xED:
      fill_none(out, M(FLDLN2));
      return X86DEC_OK;
    case 0xEE:
      fill_none(out, M(FLDZ));
      return X86DEC_OK;
    case 0xF0:
      fill_none(out, M(F2XM1));
      return X86DEC_OK;
    case 0xF1:
      fill_none(out, M(FYL2X));
      return X86DEC_OK;
    case 0xF2:
      fill_none(out, M(FPTAN));
      return X86DEC_OK;
    case 0xF3:
      fill_none(out, M(FPATN));
      return X86DEC_OK;
    case 0xF4:
      fill_none(out, M(FXTRACT));
      return X86DEC_OK;
    case 0xF5:
      fill_none(out, M(FPREM1));
      return X86DEC_OK;
    case 0xF6:
      fill_none(out, M(FDECSTP));
      return X86DEC_OK;
    case 0xF7:
      fill_none(out, M(FINCSTP));
      return X86DEC_OK;
    case 0xF8:
      fill_none(out, M(FPREM));
      return X86DEC_OK;
    case 0xF9:
      fill_none(out, M(FYL2XP1));
      return X86DEC_OK;
    case 0xFA:
      fill_none(out, M(FSQRT));
      return X86DEC_OK;
    case 0xFB:
      fill_none(out, M(FSINCOS));
      return X86DEC_OK;
    case 0xFC:
      fill_none(out, M(FRNDINT));
      return X86DEC_OK;
    case 0xFD:
      fill_none(out, M(FSCALE));
      return X86DEC_OK;
    case 0xFE:
      fill_none(out, M(FSIN));
      return X86DEC_OK;
    case 0xFF:
      fill_none(out, M(FCOS));
      return X86DEC_OK;
    default:
      return X86DEC_INVALID;
  }
}

static enum x86dec_status_e resolve_da(uint8_t modrm, X86decEntry* out)
{
  static const uint16_t fimem[8] = {
    M(FIADD), M(FIMUL), M(FICOM), M(FICOMP),
    M(FISUB), M(FISUBR), M(FIDIV), M(FIDIVR)
  };
  uint8_t reg = (uint8_t)((modrm >> 3) & 7);

  if ((modrm >> 6) != 3) {
    fill_mem(out, fimem[reg], S(MEM32_RM));
    return X86DEC_OK;
  }

  if (modrm >= 0xC0 && modrm <= 0xC7) {
    fill_pair(out, M(FCMOVB));
    return X86DEC_OK;
  }

  if (modrm >= 0xC8 && modrm <= 0xCF) {
    fill_pair(out, M(FCMOVE));
    return X86DEC_OK;
  }

  if (modrm >= 0xD0 && modrm <= 0xD7) {
    fill_pair(out, M(FCMOVBE));
    return X86DEC_OK;
  }

  if (modrm >= 0xD8 && modrm <= 0xDF) {
    fill_pair(out, M(FCMOVU));
    return X86DEC_OK;
  }

  if (modrm == 0xE9) {
    fill_none(out, M(FUCOMPP));
    return X86DEC_OK;
  }

  return X86DEC_INVALID;
}

static enum x86dec_status_e resolve_db(uint8_t modrm, X86decEntry* out)
{
  static const uint16_t mem[8] = {
    M(FILD), M(FISTTP), M(FIST), M(FISTP), 0, M(FLD), 0, M(FSTP)
  };
  static const uint8_t shapes[8] = {
    S(MEM32_RM), S(MEM32_RM), S(MEM32_RM), S(MEM32_RM),
    0, S(MEM80_RM), 0, S(MEM80_RM)
  };
  uint8_t reg = (uint8_t)((modrm >> 3) & 7);

  if ((modrm >> 6) != 3) {
    if (!mem[reg]) {
      return X86DEC_INVALID;
    }

    fill_mem(out, mem[reg], shapes[reg]);
    return X86DEC_OK;
  }

  if (modrm >= 0xC0 && modrm <= 0xC7) {
    fill_pair(out, M(FCMOVNB));
    return X86DEC_OK;
  }

  if (modrm >= 0xC8 && modrm <= 0xCF) {
    fill_pair(out, M(FCMOVNE));
    return X86DEC_OK;
  }

  if (modrm >= 0xD0 && modrm <= 0xD7) {
    fill_pair(out, M(FCMOVNBE));
    return X86DEC_OK;
  }

  if (modrm >= 0xD8 && modrm <= 0xDF) {
    fill_pair(out, M(FCMOVNU));
    return X86DEC_OK;
  }

  if (modrm >= 0xE8 && modrm <= 0xEF) {
    fill_pair(out, M(FUCOMI));
    return X86DEC_OK;
  }

  if (modrm >= 0xF0 && modrm <= 0xF7) {
    fill_pair(out, M(FCOMI));
    return X86DEC_OK;
  }

  switch (modrm) {
    case 0xE0:
      fill_none(out, M(FNENI));
      return X86DEC_OK;
    case 0xE1:
      fill_none(out, M(FNDISI));
      return X86DEC_OK;
    case 0xE2:
      fill_none(out, M(FNCLEX));
      return X86DEC_OK;
    case 0xE3:
      fill_none(out, M(FNINIT));
      return X86DEC_OK;
    case 0xE4:
      fill_none(out, M(FNSETPM));
      return X86DEC_OK;
    default:
      return X86DEC_INVALID;
  }
}

enum x86dec_status_e x86dec_resolve_fpu_low(uint8_t escape, uint8_t modrm,
    X86decEntry* out)
{
  switch (escape) {
    case 0xD8:
      return resolve_d8(modrm, out);
    case 0xD9:
      return resolve_d9(modrm, out);
    case 0xDA:
      return resolve_da(modrm, out);
    case 0xDB:
      return resolve_db(modrm, out);
    default:
      return X86DEC_INVALID;
  }
}
