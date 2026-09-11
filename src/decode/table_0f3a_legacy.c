#include "tables.h"

#define M(x) X86DEC_MNEMONIC_##x
#define S(x) X86DEC_SHAPE_##x
#define V(mn, c, s0, s1, s2, mb) {(mn), (c), {(s0), (s1), (s2)}, (mb)}
#define NOVAR {0, 0, {0, 0, 0}, 0}

const X86decSseEntry x86dec_0f3a[256] = {
[0x0F] = {
  .base = V(M(PALIGNR), 3, S(MM_REG), S(MM_OR_MEM), S(IMM8), 0),
  .variant_66 = V(M(PALIGNR), 3, S(XMM_REG), S(XMM_OR_MEM), S(IMM8), 0),
},
[0x08] = {
  .variant_66 = V(M(ROUNDPS), 2, S(XMM_REG), S(XMM_OR_MEM), S(NONE), 0),
},
[0x09] = {
  .variant_66 = V(M(ROUNDPD), 2, S(XMM_REG), S(XMM_OR_MEM), S(NONE), 0),
},
[0x0A] = {
  .variant_66 = V(M(ROUNDSS), 3, S(XMM_REG), S(XMM_OR_MEM), S(IMM8), 0),
},
[0x0B] = {
  .variant_66 = V(M(ROUNDSD), 3, S(XMM_REG), S(XMM_OR_MEM), S(IMM8), 0),
},
[0x0C] = {
  .variant_66 = V(M(BLENDPS), 3, S(XMM_REG), S(XMM_OR_MEM), S(IMM8), 0),
},
[0x0D] = {
  .variant_66 = V(M(BLENDPD), 3, S(XMM_REG), S(XMM_OR_MEM), S(IMM8), 0),
},
[0x0E] = {
  .variant_66 = V(M(PBLENDW), 3, S(XMM_REG), S(XMM_OR_MEM), S(IMM8), 0),
},
[0x14] = {
  .variant_66 = V(M(PEXTRB), 3, S(GPR_OR_MEM), S(XMM_REG), S(IMM8), 0),
},
[0x15] = {
  .variant_66 = V(M(PEXTRW), 3, S(GPR_OR_MEM), S(XMM_REG), S(IMM8), 0),
},
[0x16] = {
  .variant_66 = V(M(PEXTRD), 3, S(GPR_OR_MEM), S(XMM_REG), S(IMM8), 0),
},
[0x17] = {
  .variant_66 = V(M(EXTRACTPS), 3, S(GPR_OR_MEM), S(XMM_REG), S(IMM8), 0),
},
[0x20] = {
  .variant_66 = V(M(PINSRB), 3, S(XMM_REG), S(GPR_OR_MEM), S(IMM8), 0),
},
[0x21] = {
  .variant_66 = V(M(INSERTPS), 3, S(XMM_REG), S(XMM_OR_MEM), S(IMM8), 0),
},
[0x22] = {
  .variant_66 = V(M(PINSRD), 3, S(XMM_REG), S(GPR_OR_MEM), S(IMM8), 0),
},
[0x40] = {
  .variant_66 = V(M(DPPS), 3, S(XMM_REG), S(XMM_OR_MEM), S(IMM8), 0),
},
[0x41] = {
  .variant_66 = V(M(DPPD), 3, S(XMM_REG), S(XMM_OR_MEM), S(IMM8), 0),
},
[0x42] = {
  .variant_66 = V(M(MPSADBW), 3, S(XMM_REG), S(XMM_OR_MEM), S(IMM8), 0),
},
[0x60] = {
  .variant_66 = V(M(PCMPESTRM), 3, S(XMM_REG), S(XMM_OR_MEM), S(IMM8), 0),
},
[0x61] = {
  .variant_66 = V(M(PCMPESTRI), 3, S(XMM_REG), S(XMM_OR_MEM), S(IMM8), 0),
},
[0x62] = {
  .variant_66 = V(M(PCMPISTRM), 3, S(XMM_REG), S(XMM_OR_MEM), S(IMM8), 0),
},
[0x63] = {
  .variant_66 = V(M(PCMPISTRI), 3, S(XMM_REG), S(XMM_OR_MEM), S(IMM8), 0),
},
};
