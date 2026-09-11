#include "vex.h"

#include "tables.h"

static int vex_has_vvvv(const X86decSseVariant* v)
{
  int i;
  for (i = 0; i < 4; i++) {
    if (v->shapes[i] == X86DEC_SHAPE_VEX_VVVV ||
        v->shapes[i] == X86DEC_SHAPE_VEX_VVVV_GPR) {
      return 1;
    }
  }
  return 0;
}

static int vex_has_gpr(const X86decSseVariant* v)
{
  int i;
  for (i = 0; i < 4; i++) {
    switch (v->shapes[i]) {
      case X86DEC_SHAPE_GPR_REG:
      case X86DEC_SHAPE_GPR_RM:
      case X86DEC_SHAPE_GPR_OR_MEM:
      case X86DEC_SHAPE_VEX_VVVV_GPR:
      case X86DEC_SHAPE_R32_REG:
      case X86DEC_SHAPE_R32_OR_MEM:
      case X86DEC_SHAPE_R32_OR_MEM16:
        return 1;
      default:
        break;
    }
  }
  return 0;
}

static int vex_is_256only(uint16_t mnemonic)
{
  switch (mnemonic) {
    case X86DEC_MNEMONIC_VPERM2F128:
    case X86DEC_MNEMONIC_VEXTRACTF128:
    case X86DEC_MNEMONIC_VINSERTF128:
    case X86DEC_MNEMONIC_VBROADCASTF128:
    case X86DEC_MNEMONIC_VPERM2I128:
      return 1;
    default:
      return 0;
  }
}

static enum x86dec_status_e vex_check(const X86decSseVariant* v,
    uint8_t l, uint8_t w, uint8_t vvvv, uint8_t r, uint8_t x, uint8_t b)
{
  (void)w;
  if (v->count == 0) {
    if (vvvv != 0 || l != 0 || r != 0 || x != 0 || b != 0) {
      return X86DEC_INVALID;
    }
    return X86DEC_OK;
  }
  if (!vex_has_vvvv(v) && vvvv != 0) {
    return X86DEC_INVALID;
  }
  if (vex_has_gpr(v) && l != 0) {
    return X86DEC_INVALID;
  }
  if ((v->mem_bits == 32 || v->mem_bits == 64) && l != 0) {
    return X86DEC_INVALID;
  }
  if (vex_is_256only(v->mnemonic) && l == 0) {
    return X86DEC_INVALID;
  }
  return X86DEC_OK;
}

static void vex_fill(X86decEntry* out, const X86decSseVariant* v,
    uint8_t l, uint8_t w, uint8_t vvvv, uint8_t r, uint8_t x, uint8_t b,
    uint8_t pp, uint8_t map, uint8_t opcode)
{
  out->mnemonic = v->mnemonic;
  out->count = v->count;
  out->shapes[0] = v->shapes[0];
  out->shapes[1] = v->shapes[1];
  out->shapes[2] = v->shapes[2];
  out->shapes[3] = v->shapes[3];
  out->mem_bits = v->mem_bits;
  out->is_vex = 1;
  out->vex_l = l;
  out->vex_w = w;
  out->vex_vvvv = vvvv;
  out->vex_r = r;
  out->vex_x = x;
  out->vex_b = b;
  out->vex_pp = pp;
  out->vex_map = map;
  out->vex_opcode = opcode;
}

enum x86dec_status_e x86dec_decode_vex(const X86decDecoder* restrict decoder,
    X86decCursor* restrict cursor, X86decRaw* restrict raw,
    X86decEntry* restrict out, uint16_t* restrict fx)
{
  uint8_t b1;
  uint8_t b2;
  uint8_t b3;
  uint8_t m_mmmm;
  uint8_t w;
  uint8_t vvvv;
  uint8_t l;
  uint8_t pp;
  uint8_t map;
  uint8_t opcode;
  uint8_t r;
  uint8_t x;
  uint8_t b;

  (void)decoder;
  (void)raw;
  (void)fx;

  *out = (X86decEntry){0};

  if (!x86dec_take(cursor, &b1)) {
    return X86DEC_NEED_MORE;
  }

  if (b1 == 0xC4) {
    if (!x86dec_take(cursor, &b2)) {
      return X86DEC_NEED_MORE;
    }
    if (!x86dec_take(cursor, &b3)) {
      return X86DEC_NEED_MORE;
    }
    r = (~b2 >> 7) & 1;
    x = (~b2 >> 6) & 1;
    b = (~b2 >> 5) & 1;
    m_mmmm = b2 & 0x1F;
    w = (b3 >> 7) & 1;
    vvvv = (~b3 >> 3) & 0xF;
    l = (b3 >> 2) & 1;
    pp = b3 & 0x3;
    if (!x86dec_take(cursor, &opcode)) {
      return X86DEC_NEED_MORE;
    }
    map = m_mmmm;
    if (map < 1 || map > 3) {
      return X86DEC_INVALID;
    }
    if (map == 1 && pp == 0 && l == 0 && w == 0 && opcode == 0x77 &&
        vvvv == 0 && !r && !x && !b) {
      out->mnemonic = X86DEC_MNEMONIC_VZEROUPPER;
      out->count = 0;
      out->is_vex = 1;
      out->vex_l = l;
      out->vex_w = w;
      out->vex_vvvv = vvvv;
      out->vex_r = r;
      out->vex_x = x;
      out->vex_b = b;
      out->vex_pp = pp;
      out->vex_map = map;
      out->vex_opcode = opcode;
      return X86DEC_OK;
    }
    {
      const X86decSseEntry* e = NULL;
      if (map == 1) {
        e = &x86dec_vex_0f[opcode];
      } else if (map == 2) {
        e = &x86dec_vex_0f38[opcode];
      } else {
        e = &x86dec_vex_0f3a[opcode];
      }
      if (e) {
        const X86decSseVariant* v = &e->base;
        if (pp == 1) {
          v = &e->variant_66;
        } else if (pp == 2) {
          v = &e->variant_f3;
        } else if (pp == 3) {
          v = &e->variant_f2;
        }
        if (v->mnemonic) {
          if (vex_check(v, l, w, vvvv, r, x, b) != X86DEC_OK) {
            return X86DEC_INVALID;
          }
          vex_fill(out, v, l, w, vvvv, r, x, b, pp, map, opcode);
          return X86DEC_OK;
        }
      }
      if (map == 2 && opcode == 0xF3 && pp == 0) {
        if (l != 0) {
          return X86DEC_INVALID;
        }
        out->mnemonic = 0;
        out->count = 2;
        out->is_vex = 1;
        out->vex_l = l;
        out->vex_w = w;
        out->vex_vvvv = vvvv;
        out->vex_r = r;
        out->vex_x = x;
        out->vex_b = b;
        out->vex_pp = pp;
        out->vex_map = map;
        out->vex_opcode = opcode;
        return X86DEC_OK;
      }
      if (map == 1 && pp == 1 && opcode >= 0x71 && opcode <= 0x73) {
        if (vvvv != 0) {
          return X86DEC_INVALID;
        }
        out->mnemonic = 0;
        out->count = 2;
        out->is_vex = 1;
        out->vex_l = l;
        out->vex_w = w;
        out->vex_vvvv = vvvv;
        out->vex_r = r;
        out->vex_x = x;
        out->vex_b = b;
        out->vex_pp = pp;
        out->vex_map = map;
        out->vex_opcode = opcode;
        return X86DEC_OK;
      }
    }
    return X86DEC_UNSUPPORTED;
  }

  if (b1 == 0xC5) {
    if (!x86dec_take(cursor, &b2)) {
      return X86DEC_NEED_MORE;
    }
    r = (~b1 >> 7) & 1;
    vvvv = (~b2 >> 3) & 0xF;
    l = (b2 >> 2) & 1;
    pp = b2 & 0x3;
    w = 0;
    x = 0;
    b = 0;
    if (!x86dec_take(cursor, &opcode)) {
      return X86DEC_NEED_MORE;
    }
    if (pp == 0 && !l && opcode == 0x77 && vvvv == 0 && !r) {
      out->mnemonic = X86DEC_MNEMONIC_VZEROUPPER;
      out->count = 0;
      out->is_vex = 1;
      out->vex_l = l;
      out->vex_w = w;
      out->vex_vvvv = vvvv;
      out->vex_r = r;
      out->vex_x = x;
      out->vex_b = b;
      out->vex_pp = pp;
      out->vex_map = 1;
      out->vex_opcode = opcode;
      return X86DEC_OK;
    }
    {
      const X86decSseEntry* e = &x86dec_vex_0f[opcode];
      const X86decSseVariant* v = &e->base;
      if (pp == 1) {
        v = &e->variant_66;
      } else if (pp == 2) {
        v = &e->variant_f3;
      } else if (pp == 3) {
        v = &e->variant_f2;
      }
      if (v->mnemonic) {
        if (vex_check(v, l, w, vvvv, r, x, b) != X86DEC_OK) {
          return X86DEC_INVALID;
        }
        vex_fill(out, v, l, w, vvvv, r, x, b, pp, 1, opcode);
        return X86DEC_OK;
      }
    }
    return X86DEC_UNSUPPORTED;
  }

  return X86DEC_INVALID;
}
