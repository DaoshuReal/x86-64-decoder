#include "tables.h"

#define M(x) X86DEC_MNEMONIC_##x
#define S(x) X86DEC_SHAPE_##x

typedef struct {
  uint16_t mnemonic;
  uint8_t count;
  uint8_t s0;
  uint8_t s1;
} X86decGroup;

#define G0(mn, c, s0, s1) {(mn), (c), (s0), (s1)}
#define Z0 {0, 0, S(NONE), S(NONE)}

static const uint16_t x86dec_g1[8] = {
  M(ADD), M(OR), M(ADC), M(SBB), M(AND), M(SUB), M(XOR), M(CMP)
};

static const uint16_t x86dec_g2[8] = {
  M(ROL), M(ROR), M(RCL), M(RCR), M(SHL), M(SHR), M(SAL), M(SAR)
};

static const X86decGroup x86dec_g3b[8] = {
  G0(M(TEST), 2, S(GPR8_OR_MEM), S(IMM8)),
  G0(M(TEST), 2, S(GPR8_OR_MEM), S(IMM8)),
  G0(M(NOT), 1, S(GPR8_OR_MEM), S(NONE)),
  G0(M(NEG), 1, S(GPR8_OR_MEM), S(NONE)),
  G0(M(MUL), 1, S(GPR8_OR_MEM), S(NONE)),
  G0(M(IMUL), 1, S(GPR8_OR_MEM), S(NONE)),
  G0(M(DIV), 1, S(GPR8_OR_MEM), S(NONE)),
  G0(M(IDIV), 1, S(GPR8_OR_MEM), S(NONE))
};

static const X86decGroup x86dec_g3v[8] = {
  G0(M(TEST), 2, S(GPR_OR_MEM), S(IMM_VS)),
  G0(M(TEST), 2, S(GPR_OR_MEM), S(IMM_VS)),
  G0(M(NOT), 1, S(GPR_OR_MEM), S(NONE)),
  G0(M(NEG), 1, S(GPR_OR_MEM), S(NONE)),
  G0(M(MUL), 1, S(GPR_OR_MEM), S(NONE)),
  G0(M(IMUL), 1, S(GPR_OR_MEM), S(NONE)),
  G0(M(DIV), 1, S(GPR_OR_MEM), S(NONE)),
  G0(M(IDIV), 1, S(GPR_OR_MEM), S(NONE))
};

static const X86decGroup x86dec_g4[8] = {
  G0(M(INC), 1, S(GPR8_OR_MEM), S(NONE)),
  G0(M(DEC), 1, S(GPR8_OR_MEM), S(NONE)),
  Z0, Z0, Z0, Z0, Z0, Z0
};

static const X86decGroup x86dec_g11b[8] = {
  G0(M(MOV), 2, S(GPR8_OR_MEM), S(IMM8)),
  Z0, Z0, Z0, Z0, Z0, Z0, Z0
};

static const X86decGroup x86dec_g11v[8] = {
  G0(M(MOV), 2, S(GPR_OR_MEM), S(IMM_VS)),
  Z0, Z0, Z0, Z0, Z0, Z0, Z0
};

static const X86decGroup x86dec_g6[8] = {
  G0(M(SLDT), 1, S(GPR16_OR_MEM), S(NONE)),
  G0(M(STR), 1, S(GPR16_OR_MEM), S(NONE)),
  G0(M(LLDT), 1, S(GPR16_OR_MEM), S(NONE)),
  G0(M(LTR), 1, S(GPR16_OR_MEM), S(NONE)),
  G0(M(VERR), 1, S(GPR16_OR_MEM), S(NONE)),
  G0(M(VERW), 1, S(GPR16_OR_MEM), S(NONE)),
  Z0, Z0
};

static const uint16_t x86dec_bt[4] = {M(BT), M(BTS), M(BTR), M(BTC)};

static const uint16_t x86dec_pf[4] = {
  M(PREFETCHNTA), M(PREFETCHT0), M(PREFETCHT1), M(PREFETCHT2)
};

enum x86dec_status_e x86dec_resolve(uint8_t map, uint8_t opcode,
    uint8_t modrm, uint16_t fx, X86decEntry* out)
{
  const X86decEntry* base = map ? &x86dec_map1[opcode] : &x86dec_map0[opcode];
  int is64 = (fx & X86DEC_FX_64) != 0;
  uint8_t eosz = (uint8_t)(16 << ((fx >> X86DEC_FX_EOSZ_SHIFT) & 3));
  uint8_t easz = (uint8_t)(16 << ((fx >> X86DEC_FX_EASZ_SHIFT) & 3));
  uint8_t group = (uint8_t)(base->flags >> X86DEC_ENTRY_GROUP_SHIFT);
  uint8_t reg = (uint8_t)((modrm >> 3) & 7);
  uint8_t mod = (uint8_t)(modrm >> 6);
  const X86decGroup* g = 0;
  uint8_t i;
  if (!base->mnemonic && !group) {
    if (!map && opcode >= 0xD8) {
      return X86DEC_UNSUPPORTED;
    }
    if (map) {
      if (opcode == 0x0D || opcode == 0x0E || opcode == 0x0F ||
          opcode == 0x24 || opcode == 0x26 || opcode == 0xAA) {
        return X86DEC_UNSUPPORTED;
      }
      if (fx & (X86DEC_FX_F3 | X86DEC_FX_F2 | X86DEC_FX_66)) {
        return X86DEC_UNSUPPORTED;
      }
    }
    return X86DEC_INVALID;
  }
  *out = *base;
  if (!map) {
    switch (opcode) {
      case 0x60:
        if (is64) {
          return X86DEC_INVALID;
        }
        out->mnemonic = eosz == 16 ? M(PUSHA) : M(PUSHAD);
        break;
      case 0x61:
        if (is64) {
          return X86DEC_INVALID;
        }
        out->mnemonic = eosz == 16 ? M(POPA) : M(POPAD);
        break;
      case 0x62:
        if (is64) {
          return X86DEC_UNSUPPORTED;
        }
        break;
      case 0x63:
        if (!is64) {
          out->mnemonic = M(ARPL);
          out->shapes[0] = S(GPR16_OR_MEM);
          out->shapes[1] = S(GPR16_REG);
        }
        break;
      case 0x82:
        if (is64) {
          return X86DEC_INVALID;
        }
        break;
      case 0x8F:
        if (reg != 0) {
          return is64 ? X86DEC_UNSUPPORTED : X86DEC_INVALID;
        }
        break;
      case 0x90:
        if (fx & X86DEC_FX_F3) {
          out->mnemonic = M(PAUSE);
          out->count = 0;
        } else if (!(fx & X86DEC_FX_REX) && eosz == 32) {
          out->mnemonic = M(NOP);
          out->count = 0;
        }
        break;
      case 0x98:
        out->mnemonic = eosz == 16 ? M(CBW) : eosz == 32 ? M(CWDE) : M(CDQE);
        break;
      case 0x99:
        out->mnemonic = eosz == 16 ? M(CWD) : eosz == 32 ? M(CDQ) : M(CQO);
        break;
      case 0x9A:
      case 0xEA:
        return X86DEC_UNSUPPORTED;
      case 0xA5:
        out->mnemonic = eosz == 16 ? M(MOVSW) : eosz == 32 ? M(MOVSD) : M(MOVSQ);
        break;
      case 0xA7:
        out->mnemonic = eosz == 16 ? M(CMPSW) : eosz == 32 ? M(CMPSD) : M(CMPSQ);
        break;
      case 0xAB:
        out->mnemonic = eosz == 16 ? M(STOSW) : eosz == 32 ? M(STOSD) : M(STOSQ);
        break;
      case 0xAD:
        out->mnemonic = eosz == 16 ? M(LODSW) : eosz == 32 ? M(LODSD) : M(LODSQ);
        break;
      case 0xAF:
        out->mnemonic = eosz == 16 ? M(SCASW) : eosz == 32 ? M(SCASD) : M(SCASQ);
        break;
      case 0x6D:
        out->mnemonic = eosz == 16 ? M(INSW) : eosz == 32 ? M(INSD) : M(INSQ);
        break;
      case 0x6F:
        out->mnemonic = eosz == 16 ? M(OUTSW) : eosz == 32 ? M(OUTSD) : M(OUTSQ);
        break;
      case 0xC4:
      case 0xC5:
        if (is64) {
          return X86DEC_UNSUPPORTED;
        }
        if (mod == 3) {
          return X86DEC_INVALID;
        }
        break;
      case 0x06:
      case 0x07:
      case 0x0E:
      case 0x16:
      case 0x17:
      case 0x1E:
      case 0x1F:
      case 0x27:
      case 0x2F:
      case 0x37:
      case 0x3F:
      case 0xCE:
      case 0xD4:
      case 0xD5:
      case 0xD6:
        if (is64) {
          return X86DEC_INVALID;
        }
        break;
      case 0xCF:
        out->mnemonic = (is64 || eosz == 64) ? M(IRETQ)
            : eosz == 16 ? M(IRET) : M(IRETD);
        break;
      case 0xE3:
        out->mnemonic = easz == 64 ? M(JRCXZ) : easz == 32 ? M(JECXZ) : M(JCXZ);
        break;
      default:
        break;
    }
  } else {
    switch (opcode) {
      case 0xA0:
      case 0xA1:
      case 0xA8:
      case 0xA9:
        if (is64) {
          return X86DEC_INVALID;
        }
        break;
      case 0x1E:
        if (fx & X86DEC_FX_F3) {
          if (modrm == 0xFA) {
            out->mnemonic = M(ENDBR64);
            out->count = 0;
          } else if (modrm == 0xFB) {
            out->mnemonic = M(ENDBR32);
            out->count = 0;
          } else {
            return X86DEC_INVALID;
          }
        }
        break;
      case 0xAF:
        if (fx & X86DEC_FX_F3) {
          return X86DEC_INVALID;
        }
        break;
      case 0xB8:
        if (fx & X86DEC_FX_F3) {
          out->mnemonic = M(POPCNT);
        } else {
          return X86DEC_INVALID;
        }
        break;
      case 0xA5:
      case 0xAD:
        out->fixed[2] = 1;
        break;
      case 0xBC:
        if (fx & X86DEC_FX_F3) {
          out->mnemonic = M(TZCNT);
        }
        break;
      case 0xBD:
        if (fx & X86DEC_FX_F3) {
          out->mnemonic = M(LZCNT);
        }
        break;
      default:
        break;
    }
  }
  if (group) {
    switch (group) {
      case X86DEC_GROUP_1:
        out->mnemonic = x86dec_g1[reg];
        out->count = 2;
        if (opcode == 0x80 || opcode == 0x82) {
          out->shapes[0] = S(GPR8_OR_MEM);
          out->shapes[1] = S(IMM8);
        } else if (opcode == 0x81) {
          out->shapes[0] = S(GPR_OR_MEM);
          out->shapes[1] = S(IMM_VS);
        } else {
          out->shapes[0] = S(GPR_OR_MEM);
          out->shapes[1] = S(IMM8);
        }
        break;
      case X86DEC_GROUP_2:
        out->mnemonic = x86dec_g2[reg];
        out->count = 2;
        if (opcode == 0xC0 || opcode == 0xD0 || opcode == 0xD2) {
          out->shapes[0] = S(GPR8_OR_MEM);
        } else {
          out->shapes[0] = S(GPR_OR_MEM);
        }
        if (opcode == 0xC0 || opcode == 0xC1) {
          out->shapes[1] = S(IMM8);
        } else if (opcode == 0xD0 || opcode == 0xD1) {
          out->shapes[1] = S(IMM_ONE);
        } else {
          out->shapes[1] = S(FIXED_GPR8);
          out->fixed[1] = 1;
        }
        break;
      case X86DEC_GROUP_3B:
        g = &x86dec_g3b[reg];
        break;
      case X86DEC_GROUP_3V:
        g = &x86dec_g3v[reg];
        break;
      case X86DEC_GROUP_4:
        g = &x86dec_g4[reg];
        break;
      case X86DEC_GROUP_11B:
        g = &x86dec_g11b[reg];
        break;
      case X86DEC_GROUP_11V:
        g = &x86dec_g11v[reg];
        break;
      case X86DEC_GROUP_6:
        g = &x86dec_g6[reg];
        break;
      case X86DEC_GROUP_5:
        out->count = 1;
        out->shapes[0] = S(GPR_OR_MEM);
        switch (reg) {
          case 0:
            out->mnemonic = M(INC);
            break;
          case 1:
            out->mnemonic = M(DEC);
            break;
          case 2:
            out->mnemonic = M(CALL);
            break;
          case 3:
          case 5:
            return X86DEC_UNSUPPORTED;
          case 4:
            out->mnemonic = M(JMP);
            break;
          case 6:
            out->mnemonic = M(PUSH);
            break;
          default:
            return X86DEC_INVALID;
        }
        break;
      case X86DEC_GROUP_7:
        if (mod == 3) {
          out->count = 0;
          switch (modrm) {
            case 0xC1:
              out->mnemonic = M(VMCALL);
              break;
            case 0xC2:
              out->mnemonic = M(VMLAUNCH);
              break;
            case 0xC3:
              out->mnemonic = M(VMRESUME);
              break;
            case 0xC4:
              out->mnemonic = M(VMXOFF);
              break;
            case 0xC8:
              out->mnemonic = M(MONITOR);
              break;
            case 0xC9:
              out->mnemonic = M(MWAIT);
              break;
            case 0xD0:
              out->mnemonic = M(XGETBV);
              break;
            case 0xD1:
              out->mnemonic = M(XSETBV);
              break;
            case 0xD4:
              out->mnemonic = M(VMFUNC);
              break;
            case 0xF8:
              out->mnemonic = M(SWAPGS);
              break;
            case 0xF9:
              out->mnemonic = M(RDTSCP);
              break;
            default:
              return X86DEC_INVALID;
          }
        } else {
          out->count = 1;
          switch (reg) {
            case 0:
              out->mnemonic = M(SGDT);
              out->shapes[0] = S(MEM_RM);
              break;
            case 1:
              out->mnemonic = M(SIDT);
              out->shapes[0] = S(MEM_RM);
              break;
            case 2:
              out->mnemonic = M(LGDT);
              out->shapes[0] = S(MEM_RM);
              break;
            case 3:
              out->mnemonic = M(LIDT);
              out->shapes[0] = S(MEM_RM);
              break;
            case 4:
              out->mnemonic = M(SMSW);
              out->shapes[0] = S(GPR16_OR_MEM);
              break;
            case 6:
              out->mnemonic = M(LMSW);
              out->shapes[0] = S(GPR16_OR_MEM);
              break;
            case 7:
              out->mnemonic = M(INVLPG);
              out->shapes[0] = S(MEM8_RM);
              break;
            default:
              return X86DEC_INVALID;
          }
        }
        break;
      case X86DEC_GROUP_8:
        if (reg < 4) {
          return X86DEC_INVALID;
        }
        out->mnemonic = x86dec_bt[reg - 4];
        out->count = 2;
        out->shapes[0] = S(GPR_OR_MEM);
        out->shapes[1] = S(IMM8);
        break;
      case X86DEC_GROUP_9:
        if (mod != 3) {
          if (reg != 1) {
            return X86DEC_INVALID;
          }
          out->mnemonic = eosz == 64 ? M(CMPXCHG16B) : M(CMPXCHG8B);
          out->count = 1;
          out->shapes[0] = S(MEM_RM);
        } else if (reg == 6) {
          out->mnemonic = M(RDRAND);
          out->count = 1;
          out->shapes[0] = S(GPR_RM);
        } else if (reg == 7) {
          out->mnemonic = (fx & X86DEC_FX_F3) ? M(RDPID) : M(RDSEED);
          out->count = 1;
          out->shapes[0] = S(GPR_RM);
        } else {
          return X86DEC_INVALID;
        }
        break;
      case X86DEC_GROUP_15:
        if ((fx & X86DEC_FX_66) && (reg == 6 || reg == 7)) {
          return X86DEC_UNSUPPORTED;
        }
        if (mod == 3) {
          out->count = 0;
          if (reg == 5) {
            out->mnemonic = M(LFENCE);
          } else if (reg == 6) {
            out->mnemonic = M(MFENCE);
          } else if (reg == 7) {
            out->mnemonic = M(SFENCE);
          } else {
            return X86DEC_INVALID;
          }
        } else {
          out->count = 1;
          switch (reg) {
            case 0:
              out->mnemonic = M(FXSAVE);
              break;
            case 1:
              out->mnemonic = M(FXRSTOR);
              break;
            case 2:
              out->mnemonic = M(LDMXCSR);
              break;
            case 3:
              out->mnemonic = M(STMXCSR);
              break;
            case 4:
              out->mnemonic = M(XSAVE);
              break;
            case 5:
              out->mnemonic = M(XRSTOR);
              break;
            case 6:
              out->mnemonic = M(XSAVEOPT);
              break;
            case 7:
              out->mnemonic = M(CLFLUSH);
              break;
            default:
              return X86DEC_INVALID;
          }
          out->shapes[0] = (reg == 2 || reg == 3) ? S(MEM_RM)
              : reg == 7 ? S(MEM8_RM) : S(MEM_RM);
        }
        break;
      case X86DEC_GROUP_0F18:
        out->count = 1;
        if (reg < 4) {
          out->mnemonic = x86dec_pf[reg];
          out->shapes[0] = S(MEM8_RM);
        } else {
          out->mnemonic = M(NOP);
          out->shapes[0] = S(GPR_OR_MEM);
        }
        break;
      default:
        return X86DEC_INVALID;
    }
    if (g) {
      if (!g->mnemonic) {
        return X86DEC_INVALID;
      }
      out->mnemonic = g->mnemonic;
      out->count = g->count;
      out->shapes[0] = g->s0;
      out->shapes[1] = g->s1;
    }
  }
  if (out->flags & X86DEC_ENTRY_MODRM) {
    for (i = 0; i < out->count; i++) {
      switch (out->shapes[i]) {
        case S(MEM_RM):
        case S(MEM8_RM):
          if (mod == 3) {
            return X86DEC_INVALID;
          }
          break;
        case S(GPR_RM):
        case S(GPR8_RM):
          if (mod != 3) {
            return X86DEC_INVALID;
          }
          break;
        case S(SEG_REG):
          if (reg > 5) {
            return X86DEC_INVALID;
          }
          break;
        case S(CREG_REG):
        case S(DREG_REG):
          if (mod != 3) {
            return X86DEC_INVALID;
          }
          break;
        default:
          break;
      }
    }
  }
  return X86DEC_OK;
}
