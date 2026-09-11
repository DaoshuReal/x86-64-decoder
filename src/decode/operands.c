#include "decode/decoder.h"

#include "tables.h"
#include "core/mnemonic.h"
#include "core/register.h"

static enum x86dec_register_e gpr(uint8_t family, uint8_t slot)
{
  return (enum x86dec_register_e)(X86DEC_REG_RAX + family + slot * 16);
}

static enum x86dec_register_e gpr8(uint8_t id, uint8_t has_rex)
{
  if (!has_rex && id >= 4 && id < 8) {
    return (enum x86dec_register_e)(X86DEC_REG_AH + (id - 4));
  }
  return gpr((uint8_t)(id & 15), 3);
}

static uint8_t eosz_slot(uint8_t eosz)
{
  return eosz == 64 ? 0 : eosz == 32 ? 1 : 2;
}

static uint64_t take_imm(const X86decContext* ctx, uint8_t* off,
    uint8_t byte_count)
{
  uint64_t value = 0;
  uint8_t k;

  for (k = 0; k < byte_count; k++) {
    value |= ((ctx->imm >> ((*off + k) * 8)) & 0xFF) << (k * 8);
  }

  *off += byte_count;

  return value;
}

static uint16_t mem_size(uint16_t mnemonic, uint8_t eosz, int is64)
{
  switch (mnemonic) {
    case X86DEC_MNEMONIC_SGDT:
    case X86DEC_MNEMONIC_SIDT:
    case X86DEC_MNEMONIC_LGDT:
    case X86DEC_MNEMONIC_LIDT:
      return is64 ? 80 : 48;
    case X86DEC_MNEMONIC_LDMXCSR:
    case X86DEC_MNEMONIC_STMXCSR:
      return 32;
    case X86DEC_MNEMONIC_FXSAVE:
    case X86DEC_MNEMONIC_FXRSTOR:
    case X86DEC_MNEMONIC_XSAVE:
    case X86DEC_MNEMONIC_XRSTOR:
    case X86DEC_MNEMONIC_XSAVEOPT:
      return 4096;
    case X86DEC_MNEMONIC_FLDENV:
    case X86DEC_MNEMONIC_FNSTENV:
      return eosz == 16 ? 112 : 224;
    case X86DEC_MNEMONIC_FRSTOR:
    case X86DEC_MNEMONIC_FSAVE:
      return eosz == 16 ? 752 : 864;
    default:
      return eosz;
  }
}

static void build_mem(const X86decContext* ctx, X86decMem* mem, uint8_t seg,
    int is64)
{
  uint8_t mod = (uint8_t)(ctx->modrm >> 6);
  uint8_t rm = (uint8_t)(ctx->modrm & 7);
  uint8_t slot = ctx->easz == 64 ? 0 : ctx->easz == 32 ? 1 : 2;
  enum x86dec_register_e sp;
  enum x86dec_register_e bp;

  mem->base = X86DEC_REG_NONE;
  mem->index = X86DEC_REG_NONE;
  mem->scale = 1;
  mem->disp = ctx->disp;
  mem->has_disp = ctx->disp_size != 0;
  mem->segment = X86DEC_REG_NONE;
  if (ctx->easz == 16) {
    if (mod != 0 || rm != 6) {
      static const uint8_t bases[8] = {3, 3, 5, 5, 6, 7, 5, 3};
      static const uint8_t idxs[8] = {6, 7, 6, 7, 0xFF, 0xFF, 0xFF, 0xFF};
      mem->base = gpr(bases[rm], 2);
      if (idxs[rm] != 0xFF) {
        mem->index = gpr(idxs[rm], 2);
      }
    }
  } else {
    uint8_t ext_b = (ctx->has_rex && (ctx->rex & 1)) ? 8 : 0;
    uint8_t ext_x = (ctx->has_rex && (ctx->rex & 2)) ? 8 : 0;
    if (rm == 4) {
      uint8_t idx = (uint8_t)((ctx->sib >> 3) & 7);
      uint8_t base = (uint8_t)(ctx->sib & 7);
      if (idx != 4) {
        mem->index = gpr((uint8_t)(idx | ext_x), slot);
      }
      mem->scale = (uint8_t)(1 << (ctx->sib >> 6));
      if (mod == 0 && base == 5) {
        if (is64) {
          mem->base = X86DEC_REG_RIP;
        }
      } else {
        mem->base = gpr((uint8_t)(base | ext_b), slot);
      }
    } else if (mod == 0 && rm == 5) {
      if (is64) {
        mem->base = X86DEC_REG_RIP;
      }
    } else {
      mem->base = gpr((uint8_t)(rm | ext_b), slot);
    }
  }
  if (seg != X86DEC_REG_NONE) {
    mem->segment = (enum x86dec_register_e)seg;
  } else if (mem->base == X86DEC_REG_NONE ||
      mem->base == X86DEC_REG_RIP) {
    mem->segment = X86DEC_REG_NONE;
  } else {
    sp = gpr(4, slot);
    bp = gpr(5, slot);
    if (mem->base == sp || mem->base == bp) {
      mem->segment = X86DEC_REG_SS;
    } else {
      mem->segment = X86DEC_REG_DS;
    }
  }
}

enum x86dec_status_e x86dec_decode_operands(const X86decDecoder* decoder,
    const X86decContext* context, const X86decInsn* insn,
    X86decOperand* operands, uint8_t operand_count)
{
  uint8_t imm_off = 0;
  uint8_t regf;
  uint8_t rmf;
  uint8_t slot;
  uint8_t mod;
  uint8_t i;
  int is64;
  int cr64;

  if (!decoder || !context || !insn) {
    return X86DEC_BAD_ARG;
  }

  if (operand_count < context->count) {
    return X86DEC_BAD_ARG;
  }

  if (context->count && !operands) {
    return X86DEC_BAD_ARG;
  }

  is64 = decoder->mode == X86DEC_MODE_LONG_64;
  cr64 = is64 && context->map == 1 && context->opcode >= 0x20 &&
      context->opcode <= 0x23;
  slot = eosz_slot(context->eosz);
  regf = (uint8_t)(((context->modrm >> 3) & 7) |
      ((context->has_rex && (context->rex & 4)) ? 8 : 0));
  rmf = (uint8_t)((context->modrm & 7) |
      ((context->has_rex && (context->rex & 1)) ? 8 : 0));
  mod = (uint8_t)(context->modrm >> 6);
  for (i = 0; i < context->count; i++) {
    operands[i] = (X86decOperand){0};
  }
  for (i = 0; i < context->count; i++) {
    X86decOperand* op = &operands[i];
    uint8_t shape = context->shapes[i];
    uint8_t byte_count;
    uint64_t value;
    op->id = i;
    op->visibility = X86DEC_OPERAND_VISIBLE;
    switch (shape) {
      case X86DEC_SHAPE_GPR_REG:
        op->type = X86DEC_OPERAND_REG;
        op->reg = cr64 ? gpr(regf, 0) : gpr(regf, slot);
        op->size = cr64 ? 64 : context->eosz;
        break;
      case X86DEC_SHAPE_GPR_RM:
        op->type = X86DEC_OPERAND_REG;
        op->reg = cr64 ? gpr(rmf, 0) : gpr(rmf, slot);
        op->size = cr64 ? 64 : context->eosz;
        break;
      case X86DEC_SHAPE_GPR8_REG:
        op->type = X86DEC_OPERAND_REG;
        op->reg = gpr8(regf, context->has_rex);
        op->size = 8;
        break;
      case X86DEC_SHAPE_GPR8_RM:
        op->type = X86DEC_OPERAND_REG;
        op->reg = gpr8(rmf, context->has_rex);
        op->size = 8;
        break;
      case X86DEC_SHAPE_MEM_RM:
        op->type = X86DEC_OPERAND_MEM;
        build_mem(context, &op->mem, insn->raw.segment, is64);
        op->size = mem_size(context->mnemonic, context->eosz, is64);
        break;
      case X86DEC_SHAPE_MEM8_RM:
        op->type = X86DEC_OPERAND_MEM;
        build_mem(context, &op->mem, insn->raw.segment, is64);
        op->size = 8;
        break;
      case X86DEC_SHAPE_GPR_OR_MEM:
        if (mod == 3) {
          op->type = X86DEC_OPERAND_REG;
          op->reg = gpr(rmf, slot);
          op->size = context->eosz;
        } else {
          op->type = X86DEC_OPERAND_MEM;
          build_mem(context, &op->mem, insn->raw.segment, is64);
          op->size = context->eosz;
        }
        break;
      case X86DEC_SHAPE_GPR8_OR_MEM:
        if (mod == 3) {
          op->type = X86DEC_OPERAND_REG;
          op->reg = gpr8(rmf, context->has_rex);
          op->size = 8;
        } else {
          op->type = X86DEC_OPERAND_MEM;
          build_mem(context, &op->mem, insn->raw.segment, is64);
          op->size = 8;
        }
        break;
      case X86DEC_SHAPE_GPR16_REG:
        op->type = X86DEC_OPERAND_REG;
        op->reg = gpr(regf, 2);
        op->size = 16;
        break;
      case X86DEC_SHAPE_GPR16_OR_MEM:
        if (mod == 3) {
          op->type = X86DEC_OPERAND_REG;
          op->reg = gpr(rmf, 2);
          op->size = 16;
        } else {
          op->type = X86DEC_OPERAND_MEM;
          build_mem(context, &op->mem, insn->raw.segment, is64);
          op->size = 16;
        }
        break;
      case X86DEC_SHAPE_REG_OPCODE: {
        uint8_t fam = (uint8_t)((context->opcode & 7) |
            ((context->has_rex && (context->rex & 1)) ? 8 : 0));
        op->type = X86DEC_OPERAND_REG;
        if (context->mnemonic == X86DEC_MNEMONIC_BSWAP &&
            context->eosz == 16) {
          op->reg = gpr(fam, 1);
          op->size = 32;
        } else {
          op->reg = gpr(fam, slot);
          op->size = context->eosz;
        }
        break;
      }
      case X86DEC_SHAPE_REG8_OPCODE: {
        uint8_t fam = (uint8_t)((context->opcode & 7) |
            ((context->has_rex && (context->rex & 1)) ? 8 : 0));
        op->type = X86DEC_OPERAND_REG;
        op->reg = gpr8(fam, context->has_rex);
        op->size = 8;
        break;
      }
      case X86DEC_SHAPE_FIXED_GPR:
        op->type = X86DEC_OPERAND_REG;
        op->reg = gpr(context->fixed[i], slot);
        op->size = context->eosz;
        break;
      case X86DEC_SHAPE_FIXED_GPR8:
        op->type = X86DEC_OPERAND_REG;
        op->reg = gpr8(context->fixed[i], context->has_rex);
        op->size = 8;
        break;
      case X86DEC_SHAPE_FIXED_GPR16:
        op->type = X86DEC_OPERAND_REG;
        op->reg = gpr(context->fixed[i], 2);
        op->size = 16;
        break;
      case X86DEC_SHAPE_FIXED_SEG:
        op->type = X86DEC_OPERAND_REG;
        op->reg = (enum x86dec_register_e)(X86DEC_REG_ES + context->fixed[i]);
        op->size = 16;
        break;
      case X86DEC_SHAPE_SEG_REG:
        op->type = X86DEC_OPERAND_REG;
        op->reg = (enum x86dec_register_e)(X86DEC_REG_ES + regf);
        op->size = 16;
        break;
      case X86DEC_SHAPE_CREG_REG:
        op->type = X86DEC_OPERAND_REG;
        op->reg = (enum x86dec_register_e)(X86DEC_REG_CR0 + regf);
        op->size = cr64 ? 64 : context->eosz;
        break;
      case X86DEC_SHAPE_DREG_REG:
        op->type = X86DEC_OPERAND_REG;
        op->reg = (enum x86dec_register_e)(X86DEC_REG_DR0 + (regf & 7));
        op->size = cr64 ? 64 : context->eosz;
        break;
      case X86DEC_SHAPE_IMM8:
        op->type = X86DEC_OPERAND_IMM;
        op->imm.value = take_imm(context, &imm_off, 1);
        op->size = 8;
        break;
      case X86DEC_SHAPE_IMM16:
        op->type = X86DEC_OPERAND_IMM;
        op->imm.value = take_imm(context, &imm_off, 2);
        op->size = 16;
        break;
      case X86DEC_SHAPE_IMM_V:
        byte_count = context->eosz == 16 ? 2 : 4;
        op->type = X86DEC_OPERAND_IMM;
        op->imm.value = take_imm(context, &imm_off, byte_count);
        op->size = context->eosz == 16 ? 16 : 32;
        break;
      case X86DEC_SHAPE_IMM_V64:
        op->type = X86DEC_OPERAND_IMM;
        op->imm.value = take_imm(context, &imm_off,
            (uint8_t)(context->eosz / 8));
        op->size = context->eosz;
        break;
      case X86DEC_SHAPE_IMM_VS:
        byte_count = context->eosz == 16 ? 2 : 4;
        op->type = X86DEC_OPERAND_IMM;
        value = take_imm(context, &imm_off, byte_count);
        op->imm.value = byte_count == 2 ? (uint64_t)(int64_t)(int16_t)value
                                        : (uint64_t)(int64_t)(int32_t)value;
        op->size = context->eosz == 16 ? 16 : 32;
        break;
      case X86DEC_SHAPE_IMM_ONE:
        op->type = X86DEC_OPERAND_IMM;
        op->imm.value = 1;
        op->size = 8;
        break;
      case X86DEC_SHAPE_REL8:
        op->type = X86DEC_OPERAND_IMM;
        op->imm.value = (uint64_t)(int64_t)(int8_t)take_imm(context,
            &imm_off, 1);
        op->imm.is_relative = true;
        op->size = is64 ? 64 : context->eosz == 16 ? 16 : 32;
        break;
      case X86DEC_SHAPE_REL_V:
        byte_count = context->eosz == 16 ? 2 : 4;
        op->type = X86DEC_OPERAND_IMM;
        value = take_imm(context, &imm_off, byte_count);
        op->imm.value = byte_count == 2 ? (uint64_t)(int64_t)(int16_t)value
                                        : (uint64_t)(int64_t)(int32_t)value;
        op->imm.is_relative = true;
        op->size = is64 ? 64 : context->eosz == 16 ? 16 : 32;
        break;
      case X86DEC_SHAPE_MOFFS: {
        uint8_t j;
        op->type = X86DEC_OPERAND_MEM;
        op->mem.base = X86DEC_REG_NONE;
        op->mem.index = X86DEC_REG_NONE;
        op->mem.scale = 1;
        op->mem.disp = (int64_t)context->moffs;
        op->mem.has_disp = true;
        op->mem.segment = insn->raw.segment != X86DEC_REG_NONE
            ? insn->raw.segment : X86DEC_REG_DS;
        op->size = context->eosz;
        for (j = 0; j < context->count; j++) {
          if (context->shapes[j] == X86DEC_SHAPE_FIXED_GPR8) {
            op->size = 8;
          }
        }
        break;
      }
      case X86DEC_SHAPE_ST_REG:
        op->type = X86DEC_OPERAND_REG;
        op->reg = (enum x86dec_register_e)(X86DEC_REG_ST0 + (context->modrm & 7));
        op->size = 80;
        break;
      case X86DEC_SHAPE_FIXED_ST0:
        op->type = X86DEC_OPERAND_REG;
        op->reg = X86DEC_REG_ST0;
        op->size = 80;
        break;
      case X86DEC_SHAPE_FIXED_ST:
        op->type = X86DEC_OPERAND_REG;
        op->reg = (enum x86dec_register_e)(X86DEC_REG_ST0 + context->fixed[i]);
        op->size = 80;
        break;
      case X86DEC_SHAPE_MM_REG:
        op->type = X86DEC_OPERAND_REG;
        op->reg = (enum x86dec_register_e)(X86DEC_REG_MM0 + (regf & 7));
        op->size = 64;
        break;
      case X86DEC_SHAPE_MM_OR_MEM:
        if (mod == 3) {
          op->type = X86DEC_OPERAND_REG;
          op->reg = (enum x86dec_register_e)(X86DEC_REG_MM0 + (rmf & 7));
          op->size = 64;
        } else {
          op->type = X86DEC_OPERAND_MEM;
          build_mem(context, &op->mem, insn->raw.segment, is64);
          op->size = 64;
        }
        break;
      case X86DEC_SHAPE_XMM_REG:
        op->type = X86DEC_OPERAND_REG;
        op->reg = (enum x86dec_register_e)(X86DEC_REG_XMM0 + regf);
        op->size = 128;
        break;
      case X86DEC_SHAPE_XMM_RM:
        op->type = X86DEC_OPERAND_REG;
        op->reg = (enum x86dec_register_e)(X86DEC_REG_XMM0 + rmf);
        op->size = 128;
        break;
      case X86DEC_SHAPE_XMM_OR_MEM:
        if (mod == 3) {
          op->type = X86DEC_OPERAND_REG;
          op->reg = (enum x86dec_register_e)(X86DEC_REG_XMM0 + rmf);
          op->size = 128;
        } else {
          op->type = X86DEC_OPERAND_MEM;
          build_mem(context, &op->mem, insn->raw.segment, is64);
          op->size = context->mem_bits ? context->mem_bits : 128;
        }
        break;
      case X86DEC_SHAPE_R32_REG:
        op->type = X86DEC_OPERAND_REG;
        op->reg = gpr(regf, 1);
        op->size = 32;
        break;
      case X86DEC_SHAPE_R32_OR_MEM:
        if (mod == 3) {
          op->type = X86DEC_OPERAND_REG;
          op->reg = gpr(rmf, 1);
          op->size = 32;
        } else {
          op->type = X86DEC_OPERAND_MEM;
          build_mem(context, &op->mem, insn->raw.segment, is64);
          op->size = 32;
        }
        break;
      case X86DEC_SHAPE_MEM16_RM:
        op->type = X86DEC_OPERAND_MEM;
        build_mem(context, &op->mem, insn->raw.segment, is64);
        op->size = 16;
        break;
      case X86DEC_SHAPE_MEM32_RM:
        op->type = X86DEC_OPERAND_MEM;
        build_mem(context, &op->mem, insn->raw.segment, is64);
        op->size = 32;
        break;
      case X86DEC_SHAPE_MEM64_RM:
        op->type = X86DEC_OPERAND_MEM;
        build_mem(context, &op->mem, insn->raw.segment, is64);
        op->size = 64;
        break;
      case X86DEC_SHAPE_MEM80_RM:
        op->type = X86DEC_OPERAND_MEM;
        build_mem(context, &op->mem, insn->raw.segment, is64);
        op->size = 80;
        break;
      default:
        break;
    }
  }
  return X86DEC_OK;
}
