#include "decode/decoder.h"

#include "scan.h"
#include "tables.h"

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

enum x86dec_status_e x86dec_decode_insn(const X86decDecoder* decoder,
    X86decContext* context, const void* buffer, size_t length,
    X86decInsn* insn)
{
  X86decCursor c;
  X86decRaw raw = {0};
  X86decContext local;
  X86decEntry resolved;
  const X86decEntry* base;
  uint8_t eosz;
  uint8_t easz;
  int is64;
  uint16_t fx;
  uint8_t map = 0;
  uint8_t opcode = 0;
  uint8_t b = 0;
  uint8_t i;
  uint8_t k;
  enum x86dec_status_e st;
  if (!decoder || !buffer || !insn || !length) {
    return X86DEC_BAD_ARG;
  }
  if (!context) {
    context = &local;
  }
  *context = (X86decContext){0};
  *insn = (X86decInsn){0};
  c.p = (const uint8_t*)buffer;
  c.left = length;
  c.pos = 0;
  is64 = decoder->mode == X86DEC_MODE_LONG_64;
  eosz = x86dec_default_eosz(decoder);
  easz = x86dec_default_easz(decoder);
  st = x86dec_scan_prefixes(&c, &raw);
  if (st != X86DEC_OK) {
    return st;
  }
  if (raw.osz) {
    eosz = is64 ? 16 : (eosz == 16 ? 32 : 16);
  }
  if (raw.asz) {
    easz = is64 ? 32 : (easz == 16 ? 32 : 16);
  }
  if (is64 && c.left && (c.p[0] & 0xF0) == 0x40) {
    raw.has_rex = true;
    raw.rex = c.p[0];
    c.p++;
    c.left--;
    c.pos++;
    if (raw.rex & 0x08) {
      eosz = 64;
    }
  }
  raw.opcode_offset = (uint8_t)c.pos;
  if (!x86dec_take(&c, &opcode)) {
    return X86DEC_NEED_MORE;
  }
  if (opcode == 0x0F) {
    if (!x86dec_take(&c, &b)) {
      return X86DEC_NEED_MORE;
    }
    if (b == 0x38 || b == 0x3A) {
      map = b == 0x38 ? 2 : 3;
      if (!x86dec_take(&c, &opcode)) {
        return X86DEC_NEED_MORE;
      }
      fill_error(insn, decoder, map, opcode, c.pos);
      return X86DEC_UNSUPPORTED;
    }
    map = 1;
    opcode = b;
  }
  if (is64 && !map && (opcode == 0xC4 || opcode == 0xC5 || opcode == 0x62)) {
    fill_error(insn, decoder, map, opcode, c.pos);
    return X86DEC_UNSUPPORTED;
  }
  base = map ? &x86dec_map1[opcode] : &x86dec_map0[opcode];
  if (base->flags & X86DEC_ENTRY_MODRM) {
    st = x86dec_scan_tail(&c, easz, &raw);
    if (st != X86DEC_OK) {
      return st;
    }
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
  st = x86dec_resolve(map, opcode, raw.modrm, fx, &resolved);
  if (st != X86DEC_OK) {
    fill_error(insn, decoder, map, opcode, c.pos);
    insn->raw = raw;
    return st;
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
      case X86DEC_MNEMONIC_RETF:
      case X86DEC_MNEMONIC_ENTER:
      case X86DEC_MNEMONIC_LEAVE:
        eosz = 64;
        break;
      default:
        break;
    }
  }
  if (raw.rep) {
    switch (resolved.mnemonic) {
      case X86DEC_MNEMONIC_PAUSE:
      case X86DEC_MNEMONIC_TZCNT:
      case X86DEC_MNEMONIC_LZCNT:
      case X86DEC_MNEMONIC_RDPID:
      case X86DEC_MNEMONIC_POPCNT:
      case X86DEC_MNEMONIC_ENDBR64:
      case X86DEC_MNEMONIC_ENDBR32:
        raw.rep = false;
        break;
      default:
        break;
    }
  }
  for (i = 0; i < resolved.count; i++) {
    uint8_t n;
    if (resolved.shapes[i] == X86DEC_SHAPE_MOFFS) {
      uint8_t msize = (uint8_t)(easz / 8);
      uint64_t v = 0;
      for (k = 0; k < msize; k++) {
        if (!x86dec_take(&c, &b)) {
          return X86DEC_NEED_MORE;
        }
        v |= (uint64_t)b << (k * 8);
      }
      raw.has_moffs = true;
      raw.moffs = v;
      continue;
    }
    n = shape_imm_bytes(resolved.shapes[i], eosz);
    for (k = 0; k < n; k++) {
      if (!x86dec_take(&c, &b)) {
        return X86DEC_NEED_MORE;
      }
      raw.imm |= (uint64_t)b << (raw.imm_size * 8);
      raw.imm_size++;
    }
  }
  if (c.pos > X86DEC_MAX_INSN_LENGTH) {
    fill_error(insn, decoder, map, opcode, c.pos);
    insn->raw = raw;
    return X86DEC_INVALID;
  }
  insn->mode = decoder->mode;
  insn->mnemonic = (enum x86dec_mnemonic_e)resolved.mnemonic;
  insn->length = (uint8_t)c.pos;
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
  context->length = (uint8_t)c.pos;
  context->opcode = opcode;
  context->map = map;
  context->flags = insn->flags;
  return X86DEC_OK;
}

enum x86dec_status_e x86dec_decode_full(const X86decDecoder* decoder,
    const void* buffer, size_t length, X86decInsn* insn,
    X86decOperand* operands, uint8_t operand_count)
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
