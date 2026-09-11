#include "decode/decoder.h"

#include "scan.h"
#include "tables.h"
#include "vex.h"

static uint8_t shape_imm_bytes(uint8_t shape, uint8_t eosz)
{
  switch (shape) {
    case X86DEC_SHAPE_IMM8:
    case X86DEC_SHAPE_REL8:
      return 1;
    case X86DEC_SHAPE_IMM16:
      return 2;
    case X86DEC_SHAPE_IMM_V:
    case X86DEC_SHAPE_IMM_VS:
    case X86DEC_SHAPE_REL_V:
      return eosz == 16 ? 2 : 4;
    case X86DEC_SHAPE_IMM_V64:
      return (uint8_t)(eosz / 8);
    default:
      return 0;
  }
}

static void fill_error(X86decInsn* insn, const X86decDecoder* decoder,
    uint8_t map, uint8_t opcode, size_t pos)
{
  *insn = (X86decInsn){0};
  insn->mode = decoder->mode;
  insn->map = map;
  insn->opcode = opcode;
  insn->stack_width = (uint8_t)decoder->width;
  insn->length = pos > 15 ? 15 : (uint8_t)pos;
}

bool x86dec_decoder_init(X86decDecoder* decoder,
    enum x86dec_machine_mode_e mode, enum x86dec_stack_width_e width)
{
  if (!decoder) {
    return false;
  }

  if (mode > X86DEC_MODE_REAL_16) {
    return false;
  }

  if (mode == X86DEC_MODE_LONG_64) {
    if (width != X86DEC_STACK_64) {
      return false;
    }
  } else if (width == X86DEC_STACK_64) {
    return false;
  }

  decoder->mode = mode;
  decoder->width = width;

  return true;
}

enum x86dec_status_e x86dec_decode_insn(const X86decDecoder* restrict decoder,
    X86decContext* restrict context, const void* restrict buffer, size_t length,
    X86decInsn* restrict insn)
{
  X86decCursor cursor;
  X86decRaw raw = {0};
  X86decContext local;
  X86decEntry resolved = {0};
  const X86decEntry* base;
  uint8_t eosz;
  uint8_t easz;
  int is64;
  uint16_t fx;
  uint8_t map = 0;
  uint8_t opcode = 0;
  uint8_t tail = 0;
  uint8_t b = 0;
  uint8_t i;
  uint8_t k;
  X86decEntry synth = {0};
  int use_synth = 0;
  enum x86dec_status_e st;

  if (X86DEC_UNLIKELY(!decoder || !buffer || !insn || !length)) {
    return X86DEC_BAD_ARG;
  }

  if (!context) {
    context = &local;
  }

  *context = (X86decContext){0};
  *insn = (X86decInsn){0};

  cursor.p = (const uint8_t*)buffer;
  cursor.left = length;
  cursor.pos = 0;

  is64 = decoder->mode == X86DEC_MODE_LONG_64;
  eosz = x86dec_default_eosz(decoder);
  easz = x86dec_default_easz(decoder);

  st = x86dec_scan_prefixes(&cursor, &raw);

  if (X86DEC_UNLIKELY(st != X86DEC_OK)) {
    return st;
  }

  if (raw.osz) {
    eosz = is64 ? 16 : (eosz == 16 ? 32 : 16);
  }

  if (raw.asz) {
    easz = is64 ? 32 : (easz == 16 ? 32 : 16);
  }

  if (X86DEC_LIKELY(is64) && X86DEC_LIKELY(cursor.left) &&
      (cursor.p[0] & 0xF0) == 0x40) {
    raw.has_rex = true;
    raw.rex = cursor.p[0];
    cursor.p++;
    cursor.left--;
    cursor.pos++;

    if (raw.rex & 0x08) {
      eosz = 64;
    }
  }

  raw.opcode_offset = (uint8_t)cursor.pos;

  if (X86DEC_UNLIKELY(!x86dec_take(&cursor, &opcode))) {
    return X86DEC_NEED_MORE;
  }

  if (opcode == 0x0F) {
    if (X86DEC_UNLIKELY(!x86dec_take(&cursor, &b))) {
      return X86DEC_NEED_MORE;
    }

    if (b == 0x38 || b == 0x3A) {
      map = b == 0x38 ? 2 : 3;

      if (X86DEC_UNLIKELY(!x86dec_take(&cursor, &opcode))) {
        return X86DEC_NEED_MORE;
      }
    } else {
      map = 1;
      opcode = b;
    }
  }

  if (X86DEC_UNLIKELY(is64 && !map && opcode == 0xC4 && cursor.left >= 3 &&
      cursor.p[0] == 0xE1 && cursor.p[1] == 0x7C && cursor.p[2] == 0xC0)) {
    cursor.p += 3;
    cursor.left -= 3;
    cursor.pos += 3;
    synth.mnemonic = X86DEC_MNEMONIC_VZEROALL;
    use_synth = 1;
  } else if (X86DEC_UNLIKELY(is64 && !map &&
      (opcode == 0xC4 || opcode == 0xC5))) {
    cursor.p--;
    cursor.left++;
    cursor.pos--;

    {
      enum x86dec_status_e vs = x86dec_decode_vex(decoder, &cursor, &raw, &synth, &fx);

      if (X86DEC_LIKELY(vs == X86DEC_OK)) {
        use_synth = 1;
      } else {
        fill_error(insn, decoder, map, opcode, cursor.pos);
        return vs;
      }
    }
  } else if (X86DEC_UNLIKELY(is64 && !map && opcode == 0x62)) {
    fill_error(insn, decoder, map, opcode, cursor.pos);
    return X86DEC_UNSUPPORTED;
  }

  fx = (uint16_t)(is64 ? X86DEC_FX_64 : 0);
  fx |= (uint16_t)((eosz == 16 ? 0 : eosz == 32 ? 1 : 2)
      << X86DEC_FX_EOSZ_SHIFT);
  fx |= (uint16_t)((easz == 16 ? 0 : easz == 32 ? 1 : 2)
      << X86DEC_FX_EASZ_SHIFT);

  if (raw.rep) {
    fx |= X86DEC_FX_F3;
  }

  if (raw.repne) {
    fx |= X86DEC_FX_F2;
  }

  if (raw.osz) {
    fx |= X86DEC_FX_66;
  }

  if (raw.has_rex && (raw.rex & 0x08)) {
    fx |= X86DEC_FX_REXW;
  }

  if (raw.has_rex && (raw.rex & 0x01)) {
    fx |= X86DEC_FX_REXB;
  }

  if (raw.has_rex) {
    fx |= X86DEC_FX_REX;
  }

  if (X86DEC_UNLIKELY(use_synth)) {
    resolved = synth;
    if (raw.lock) {
      fill_error(insn, decoder, map, opcode, cursor.pos);
      insn->raw = raw;
      return X86DEC_INVALID;
    }
    if (raw.has_rex) {
      fill_error(insn, decoder, map, opcode, cursor.pos);
      insn->raw = raw;
      return X86DEC_INVALID;
    }
    if (resolved.count > 0) {
      st = x86dec_scan_tail(&cursor, easz, &raw);
      if (st != X86DEC_OK) {
        return st;
      }
      {
        uint8_t mod = (uint8_t)(raw.modrm >> 6);
        uint8_t reg = (uint8_t)((raw.modrm >> 3) & 7);
        uint8_t k;
        if (resolved.mnemonic == 0 && resolved.is_vex &&
            resolved.vex_map == 2 && resolved.vex_opcode == 0xF3 &&
            resolved.vex_pp == 0) {
          uint8_t l = resolved.vex_l;
          if (l != 0) {
            fill_error(insn, decoder, map, opcode, cursor.pos);
            insn->raw = raw;
            return X86DEC_INVALID;
          }
          resolved.count = 2;
          resolved.shapes[0] = X86DEC_SHAPE_VEX_VVVV_GPR;
          resolved.shapes[1] = X86DEC_SHAPE_GPR_OR_MEM;
          resolved.shapes[2] = X86DEC_SHAPE_NONE;
          resolved.shapes[3] = X86DEC_SHAPE_NONE;
          switch (reg) {
            case 1:
              resolved.mnemonic = X86DEC_MNEMONIC_BLSR;
              break;
            case 2:
              resolved.mnemonic = X86DEC_MNEMONIC_BLSMSK;
              break;
            case 3:
              resolved.mnemonic = X86DEC_MNEMONIC_BLSI;
              break;
            default:
              fill_error(insn, decoder, map, opcode, cursor.pos);
              insn->raw = raw;
              return X86DEC_INVALID;
          }
        }
        if (resolved.mnemonic == 0 && resolved.is_vex &&
            resolved.vex_map == 1 && resolved.vex_pp == 1 &&
            resolved.vex_opcode >= 0x71 && resolved.vex_opcode <= 0x73) {
          uint8_t vex_op = resolved.vex_opcode;
          resolved.count = 2;
          resolved.shapes[1] = X86DEC_SHAPE_IMM8;
          resolved.shapes[2] = X86DEC_SHAPE_NONE;
          resolved.shapes[3] = X86DEC_SHAPE_NONE;
          if (vex_op == 0x71) {
            resolved.shapes[0] = X86DEC_SHAPE_XMM_OR_MEM;
            switch (reg) {
              case 2:
                resolved.mnemonic = X86DEC_MNEMONIC_VPSRLW;
                break;
              case 4:
                resolved.mnemonic = X86DEC_MNEMONIC_VPSRAW;
                break;
              case 6:
                resolved.mnemonic = X86DEC_MNEMONIC_VPSLLW;
                break;
              default:
                fill_error(insn, decoder, map, opcode, cursor.pos);
                insn->raw = raw;
                return X86DEC_INVALID;
            }
          } else if (vex_op == 0x72) {
            resolved.shapes[0] = X86DEC_SHAPE_XMM_OR_MEM;
            switch (reg) {
              case 2:
                resolved.mnemonic = X86DEC_MNEMONIC_VPSRLD;
                break;
              case 4:
                resolved.mnemonic = X86DEC_MNEMONIC_VPSRAD;
                break;
              case 6:
                resolved.mnemonic = X86DEC_MNEMONIC_VPSLLD;
                break;
              default:
                fill_error(insn, decoder, map, opcode, cursor.pos);
                insn->raw = raw;
                return X86DEC_INVALID;
            }
          } else {
            resolved.shapes[0] = X86DEC_SHAPE_XMM_OR_MEM;
            switch (reg) {
              case 2:
                resolved.mnemonic = X86DEC_MNEMONIC_VPSRLQ;
                break;
              case 3:
                resolved.mnemonic = X86DEC_MNEMONIC_VPSRLDQ;
                break;
              case 6:
                resolved.mnemonic = X86DEC_MNEMONIC_VPSLLQ;
                break;
              case 7:
                resolved.mnemonic = X86DEC_MNEMONIC_VPSLLDQ;
                break;
              default:
                fill_error(insn, decoder, map, opcode, cursor.pos);
                insn->raw = raw;
                return X86DEC_INVALID;
            }
            if ((resolved.mnemonic == X86DEC_MNEMONIC_VPSRLDQ ||
                resolved.mnemonic == X86DEC_MNEMONIC_VPSLLDQ) &&
                resolved.vex_l != 0) {
              fill_error(insn, decoder, map, opcode, cursor.pos);
              insn->raw = raw;
              return X86DEC_INVALID;
            }
          }
        }
        if (resolved.mnemonic == 0) {
          fill_error(insn, decoder, map, opcode, cursor.pos);
          insn->raw = raw;
          return X86DEC_UNSUPPORTED;
        }
        for (k = 0; k < resolved.count; k++) {
          switch (resolved.shapes[k]) {
            case X86DEC_SHAPE_MEM_RM:
            case X86DEC_SHAPE_MEM8_RM:
            case X86DEC_SHAPE_MEM16_RM:
            case X86DEC_SHAPE_MEM32_RM:
            case X86DEC_SHAPE_MEM64_RM:
            case X86DEC_SHAPE_MEM80_RM:
              if (mod == 3) {
                fill_error(insn, decoder, map, opcode, cursor.pos);
                insn->raw = raw;
                return X86DEC_INVALID;
              }
              break;
            case X86DEC_SHAPE_GPR_RM:
            case X86DEC_SHAPE_GPR8_RM:
            case X86DEC_SHAPE_XMM_RM:
            case X86DEC_SHAPE_XMM32:
            case X86DEC_SHAPE_XMM64:
            case X86DEC_SHAPE_MM32:
            case X86DEC_SHAPE_MM_RM:
            case X86DEC_SHAPE_YMM_RM:
            case X86DEC_SHAPE_YMM32:
            case X86DEC_SHAPE_YMM64:
              if (mod != 3) {
                fill_error(insn, decoder, map, opcode, cursor.pos);
                insn->raw = raw;
                return X86DEC_INVALID;
              }
              break;
            default:
              break;
          }
        }
        switch (resolved.mnemonic) {
          case X86DEC_MNEMONIC_VMOVNTPS:
          case X86DEC_MNEMONIC_VMOVNTPD:
          case X86DEC_MNEMONIC_VMOVNTDQ:
          case X86DEC_MNEMONIC_VMOVNTDQA:
          case X86DEC_MNEMONIC_VBROADCASTSS:
          case X86DEC_MNEMONIC_VBROADCASTSD:
          case X86DEC_MNEMONIC_VBROADCASTF128:
          case X86DEC_MNEMONIC_VMASKMOVPS:
          case X86DEC_MNEMONIC_VMASKMOVPD:
            if (mod == 3) {
              int need_mem = 0;
              if (resolved.mnemonic == X86DEC_MNEMONIC_VMOVNTPS ||
                  resolved.mnemonic == X86DEC_MNEMONIC_VMOVNTPD ||
                  resolved.mnemonic == X86DEC_MNEMONIC_VMOVNTDQ) {
                need_mem = 1;
              }
              if (need_mem) {
                fill_error(insn, decoder, map, opcode, cursor.pos);
                insn->raw = raw;
                return X86DEC_INVALID;
              }
            }
            break;
          default:
            break;
        }
      }
    }
  } else if (X86DEC_UNLIKELY(map >= 2)) {
    st = x86dec_scan_tail(&cursor, easz, &raw);

    if (X86DEC_UNLIKELY(st != X86DEC_OK)) {
      return st;
    }

    st = x86dec_resolve_crypto(map, opcode, raw.modrm, fx, &resolved);

    if (X86DEC_UNLIKELY(st != X86DEC_OK)) {
      fill_error(insn, decoder, map, opcode, cursor.pos);
      insn->raw = raw;
      return st;
    }
  } else {
    base = map ? &x86dec_map1[opcode] : &x86dec_map0[opcode];

    if (base->flags & X86DEC_ENTRY_MODRM) {
      st = x86dec_scan_tail(&cursor, easz, &raw);

      if (X86DEC_UNLIKELY(st != X86DEC_OK)) {
        return st;
      }
    }

    tail = 0;

    if (X86DEC_UNLIKELY(map == 1 && opcode == 0x0F)) {
      if (X86DEC_UNLIKELY(!x86dec_take(&cursor, &tail))) {
        return X86DEC_NEED_MORE;
      }
    }

    st = x86dec_resolve(map, opcode, raw.modrm, tail, fx, &resolved);

    if (X86DEC_UNLIKELY(st != X86DEC_OK)) {
      fill_error(insn, decoder, map, opcode, cursor.pos);
      insn->raw = raw;
      return st;
    }
  }

  if (is64 && eosz == 32) {
    switch (resolved.mnemonic) {
      case X86DEC_MNEMONIC_PUSH:
      case X86DEC_MNEMONIC_POP:
      case X86DEC_MNEMONIC_PUSHF:
      case X86DEC_MNEMONIC_POPF:
      case X86DEC_MNEMONIC_CALL:
      case X86DEC_MNEMONIC_JMP:
      case X86DEC_MNEMONIC_RET:
      case X86DEC_MNEMONIC_ENTER:
      case X86DEC_MNEMONIC_LEAVE:
        eosz = 64;
        break;
      default:
        break;
    }
  }

  if (resolved.mnemonic == X86DEC_MNEMONIC_MOVQ) {
    eosz = 64;
  }

  if (map >= 1) {
    raw.rep = false;
    raw.repne = false;
  } else if (raw.rep && resolved.mnemonic == X86DEC_MNEMONIC_PAUSE) {
    raw.rep = false;
  }

  for (i = 0; i < resolved.count; i++) {
    uint8_t byte_count;

    if (resolved.shapes[i] == X86DEC_SHAPE_MOFFS) {
      uint8_t moffs_size = (uint8_t)(easz / 8);
      uint64_t value = 0;

      for (k = 0; k < moffs_size; k++) {
        if (!x86dec_take(&cursor, &b)) {
          return X86DEC_NEED_MORE;
        }

        value |= (uint64_t)b << (k * 8);
      }

      raw.has_moffs = true;
      raw.moffs = value;
      continue;
    }

    byte_count = shape_imm_bytes(resolved.shapes[i], eosz);

    for (k = 0; k < byte_count; k++) {
      if (X86DEC_UNLIKELY(!x86dec_take(&cursor, &b))) {
        return X86DEC_NEED_MORE;
      }

      raw.imm |= (uint64_t)b << (raw.imm_size * 8);
      raw.imm_size++;
    }
  }

  if (X86DEC_UNLIKELY(cursor.pos > X86DEC_MAX_INSN_LENGTH)) {
    fill_error(insn, decoder, map, opcode, cursor.pos);
    insn->raw = raw;
    return X86DEC_INVALID;
  }

  insn->mode = decoder->mode;
  insn->mnemonic = (enum x86dec_mnemonic_e)resolved.mnemonic;
  insn->length = (uint8_t)cursor.pos;
  insn->map = map;
  insn->opcode = opcode;
  insn->stack_width = (uint8_t)decoder->width;
  insn->operand_width = eosz;
  insn->address_width = easz;
  insn->operand_count = resolved.count;
  insn->flags = 0;

  if (raw.lock) {
    insn->flags |= X86DEC_INSN_HAS_LOCK;
  }

  if (raw.rep) {
    insn->flags |= X86DEC_INSN_HAS_REP;
  }

  if (raw.repne) {
    insn->flags |= X86DEC_INSN_HAS_REPNE;
  }

  if (raw.has_rex) {
    insn->flags |= X86DEC_INSN_HAS_REX;
  }

  if (raw.has_modrm) {
    insn->flags |= X86DEC_INSN_HAS_MODRM;
  }

  if (raw.has_sib) {
    insn->flags |= X86DEC_INSN_HAS_SIB;
  }

  if (raw.osz) {
    insn->flags |= X86DEC_INSN_OSZ_OVERRIDE;
  }

  if (raw.asz) {
    insn->flags |= X86DEC_INSN_ASZ_OVERRIDE;
  }

  insn->raw = raw;

  context->eosz = eosz;
  context->easz = easz;
  context->has_rex = raw.has_rex;
  context->rex = raw.rex;
  context->modrm = raw.modrm;
  context->has_modrm = raw.has_modrm;
  context->sib = raw.sib;
  context->has_sib = raw.has_sib;
  context->disp = raw.disp;
  context->disp_size = raw.disp_size;
  context->moffs = raw.moffs;
  context->has_moffs = raw.has_moffs;
  context->imm = raw.imm;
  context->imm_size = raw.imm_size;
  context->mnemonic = resolved.mnemonic;
  context->count = resolved.count;
  context->shapes[0] = resolved.shapes[0];
  context->shapes[1] = resolved.shapes[1];
  context->shapes[2] = resolved.shapes[2];
  context->fixed[0] = resolved.fixed[0];
  context->fixed[1] = resolved.fixed[1];
  context->fixed[2] = resolved.fixed[2];
  context->length = (uint8_t)cursor.pos;
  context->flags = insn->flags;
  context->mem_bits = resolved.mem_bits;
  context->is_vex = resolved.is_vex;
  if (resolved.is_vex) {
    context->shapes[3] = resolved.shapes[3];
    context->fixed[3] = resolved.fixed[3];
    context->vex_l = resolved.vex_l;
    context->vex_w = resolved.vex_w;
    context->vex_vvvv = resolved.vex_vvvv;
    context->vex_r = resolved.vex_r;
    context->vex_x = resolved.vex_x;
    context->vex_b = resolved.vex_b;
    context->vex_pp = resolved.vex_pp;
    context->vex_map = resolved.vex_map;
    context->vex_opcode = resolved.vex_opcode;
  }
  if (resolved.is_vex) {
    context->opcode = resolved.vex_opcode;
    context->map = resolved.vex_map;
  } else {
    context->opcode = opcode;
    context->map = map;
  }

  insn->map = context->map;
  insn->opcode = context->opcode;

  return X86DEC_OK;
}

enum x86dec_status_e x86dec_decode_full(const X86decDecoder* restrict decoder,
    const void* restrict buffer, size_t length, X86decInsn* restrict insn,
    X86decOperand* restrict operands, uint8_t operand_count)
{
  X86decContext context;
  enum x86dec_status_e st;

  if (!operands && operand_count) {
    return X86DEC_BAD_ARG;
  }

  st = x86dec_decode_insn(decoder, &context, buffer, length, insn);

  if (st != X86DEC_OK) {
    return st;
  }

  return x86dec_decode_operands(decoder, &context, insn, operands,
      operand_count);
}
