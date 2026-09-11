#include "tables.h"

#define M(x) X86DEC_MNEMONIC_##x
#define S(x) X86DEC_SHAPE_##x

static void fpu2_fill_mem(X86decEntry* out, uint16_t mnemonic, uint8_t shape)
{
  out->mnemonic = mnemonic;
  out->count = 1;
  out->shapes[0] = shape;
  out->shapes[1] = S(NONE);
  out->shapes[2] = S(NONE);
}

static void fpu2_fill_none(X86decEntry* out, uint16_t mnemonic)
{
  out->mnemonic = mnemonic;
  out->count = 0;
  out->shapes[0] = S(NONE);
  out->shapes[1] = S(NONE);
  out->shapes[2] = S(NONE);
}

static void fpu2_fill_pair(X86decEntry* out, uint16_t mnemonic)
{
  out->mnemonic = mnemonic;
  out->count = 2;
  out->shapes[0] = S(FIXED_ST0);
  out->shapes[1] = S(ST_REG);
  out->shapes[2] = S(NONE);
}

static void fpu2_fill_pair_rev(X86decEntry* out, uint16_t mnemonic)
{
  out->mnemonic = mnemonic;
  out->count = 2;
  out->shapes[0] = S(ST_REG);
  out->shapes[1] = S(FIXED_ST0);
  out->shapes[2] = S(NONE);
}

static void fpu2_fill_st(X86decEntry* out, uint16_t mnemonic)
{
  out->mnemonic = mnemonic;
  out->count = 1;
  out->shapes[0] = S(ST_REG);
  out->shapes[1] = S(NONE);
  out->shapes[2] = S(NONE);
}

static enum x86dec_status_e resolve_dc(uint8_t modrm, X86decEntry* out)
{
  static const uint16_t arith[8] = {
    M(FADD), M(FMUL), M(FCOM), M(FCOMP), M(FSUB), M(FSUBR), M(FDIV), M(FDIVR)
  };
  uint8_t reg = (uint8_t)((modrm >> 3) & 7);

  if ((modrm >> 6) != 3) {
    fpu2_fill_mem(out, arith[reg], S(MEM64_RM));
    return X86DEC_OK;
  }

  if (reg == 0) {
    fpu2_fill_pair_rev(out, M(FADD));
    return X86DEC_OK;
  }

  if (reg == 1) {
    fpu2_fill_pair_rev(out, M(FMUL));
    return X86DEC_OK;
  }

  if (modrm >= 0xD0 && modrm <= 0xD7) {
    fpu2_fill_st(out, M(FCOM));
    return X86DEC_OK;
  }

  if (modrm >= 0xD8 && modrm <= 0xDF) {
    fpu2_fill_st(out, M(FCOMP));
    return X86DEC_OK;
  }

  return X86DEC_INVALID;
}

static enum x86dec_status_e resolve_dd(uint8_t modrm, X86decEntry* out)
{
  static const uint16_t mem[8] = {
    M(FLD), M(FISTTP), M(FST), M(FSTP), M(FRSTOR), 0, M(FSAVE),
    M(FNSTSW)
  };
  static const uint8_t shapes[8] = {
    S(MEM64_RM), S(MEM64_RM), S(MEM64_RM), S(MEM64_RM),
    S(MEM_RM), S(MEM64_RM), S(MEM_RM), S(MEM16_RM)
  };
  uint8_t reg = (uint8_t)((modrm >> 3) & 7);

  if ((modrm >> 6) != 3) {
    if (!mem[reg]) {
      return X86DEC_INVALID;
    }

    fpu2_fill_mem(out, mem[reg], shapes[reg]);
    return X86DEC_OK;
  }

  if (modrm >= 0xC0 && modrm <= 0xC7) {
    fpu2_fill_st(out, M(FFREE));
    return X86DEC_OK;
  }

  if (modrm >= 0xC8 && modrm <= 0xCF) {
    fpu2_fill_st(out, M(FXCH));
    return X86DEC_OK;
  }

  if (modrm >= 0xD0 && modrm <= 0xD7) {
    fpu2_fill_st(out, M(FST));
    return X86DEC_OK;
  }

  if (modrm >= 0xD8 && modrm <= 0xDF) {
    fpu2_fill_st(out, M(FSTP));
    return X86DEC_OK;
  }

  if (modrm >= 0xE0 && modrm <= 0xE7) {
    fpu2_fill_st(out, M(FUCOM));
    return X86DEC_OK;
  }

  if (modrm >= 0xE8 && modrm <= 0xEF) {
    out->mnemonic = M(FUCOMP);
    out->count = 2;
    out->shapes[0] = S(IMPLICIT_ST0);
    out->shapes[1] = S(ST_REG);
    out->shapes[2] = S(NONE);
    return X86DEC_OK;
  }

  return X86DEC_INVALID;
}

static enum x86dec_status_e resolve_de(uint8_t modrm, X86decEntry* out)
{
  static const uint16_t fimem[8] = {
    M(FIADD), M(FIMUL), M(FICOM), M(FICOMP),
    M(FISUB), M(FISUBR), M(FIDIV), M(FIDIVR)
  };
  uint8_t reg = (uint8_t)((modrm >> 3) & 7);

  if ((modrm >> 6) != 3) {
    fpu2_fill_mem(out, fimem[reg], S(MEM16_RM));
    return X86DEC_OK;
  }

  if (modrm >= 0xC0 && modrm <= 0xC7) {
    fpu2_fill_pair_rev(out, M(FADDP));
    return X86DEC_OK;
  }

  if (modrm >= 0xC8 && modrm <= 0xCF) {
    fpu2_fill_pair_rev(out, M(FMULP));
    return X86DEC_OK;
  }

  if (modrm == 0xD9) {
    fpu2_fill_none(out, M(FCOMPP));
    return X86DEC_OK;
  }

  if ((modrm >= 0xD0 && modrm <= 0xD8) ||
      (modrm >= 0xDA && modrm <= 0xDF)) {
    fpu2_fill_st(out, M(FCOMP));
    return X86DEC_OK;
  }

  if (modrm >= 0xE0 && modrm <= 0xE7) {
    fpu2_fill_pair_rev(out, M(FSUBRP));
    return X86DEC_OK;
  }

  if (modrm >= 0xE8 && modrm <= 0xEF) {
    fpu2_fill_pair_rev(out, M(FSUBP));
    return X86DEC_OK;
  }

  if (modrm >= 0xF0 && modrm <= 0xF7) {
    fpu2_fill_pair_rev(out, M(FDIVRP));
    return X86DEC_OK;
  }

  if (modrm >= 0xF8 && modrm <= 0xFF) {
    fpu2_fill_pair_rev(out, M(FDIVP));
    return X86DEC_OK;
  }

  return X86DEC_INVALID;
}

static enum x86dec_status_e resolve_df(uint8_t modrm, X86decEntry* out)
{
  static const uint16_t mem[8] = {
    M(FILD), M(FISTTP), M(FIST), M(FISTP),
    M(FBLD), M(FILD), M(FBSTP), M(FISTP)
  };
  static const uint8_t shapes[8] = {
    S(MEM16_RM), S(MEM16_RM), S(MEM16_RM), S(MEM16_RM),
    S(MEM80_RM), S(MEM64_RM), S(MEM80_RM), S(MEM64_RM)
  };
  uint8_t reg = (uint8_t)((modrm >> 3) & 7);

  if ((modrm >> 6) != 3) {
    fpu2_fill_mem(out, mem[reg], shapes[reg]);
    return X86DEC_OK;
  }

  if (modrm >= 0xC0 && modrm <= 0xC7) {
    fpu2_fill_st(out, M(FFREEP));
    return X86DEC_OK;
  }

  if (modrm >= 0xD0 && modrm <= 0xD7) {
    fpu2_fill_st(out, M(FSTP));
    return X86DEC_OK;
  }

  if (modrm >= 0xE8 && modrm <= 0xEF) {
    fpu2_fill_pair(out, M(FUCOMIP));
    return X86DEC_OK;
  }

  if (modrm >= 0xF0 && modrm <= 0xF7) {
    fpu2_fill_pair(out, M(FCOMIP));
    return X86DEC_OK;
  }

  if (modrm == 0xE0) {
    out->mnemonic = M(FNSTSW);
    out->count = 1;
    out->shapes[0] = S(FIXED_GPR16);
    out->shapes[1] = S(NONE);
    out->shapes[2] = S(NONE);
    out->fixed[0] = 0;
    return X86DEC_OK;
  }

  return X86DEC_INVALID;
}

enum x86dec_status_e x86dec_resolve_fpu_high(uint8_t escape, uint8_t modrm,
    X86decEntry* out)
{
  switch (escape) {
    case 0xDC:
      return resolve_dc(modrm, out);
    case 0xDD:
      return resolve_dd(modrm, out);
    case 0xDE:
      return resolve_de(modrm, out);
    case 0xDF:
      return resolve_df(modrm, out);
    default:
      return X86DEC_INVALID;
  }
}
