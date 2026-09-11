#include "tables.h"

#define M(x) X86DEC_MNEMONIC_##x
#define S(x) X86DEC_SHAPE_##x
#define V(mn, c, s0, s1, s2, mb) {(mn), (c), {(s0), (s1), (s2)}, (mb)}
#define NOVAR {0, 0, {0, 0, 0}, 0}

const X86decSseEntry x86dec_0f38[256] = {
[0x00] = {
  .base = V(M(PSHUFB), 2, S(MM_REG), S(MM_OR_MEM), S(NONE), 0),
  .variant_66 = V(M(PSHUFB), 2, S(XMM_REG), S(XMM_OR_MEM), S(NONE), 0),
},
[0x01] = {
  .base = V(M(PHADDW), 2, S(MM_REG), S(MM_OR_MEM), S(NONE), 0),
  .variant_66 = V(M(PHADDW), 2, S(XMM_REG), S(XMM_OR_MEM), S(NONE), 0),
},
[0x02] = {
  .base = V(M(PHADDD), 2, S(MM_REG), S(MM_OR_MEM), S(NONE), 0),
  .variant_66 = V(M(PHADDD), 2, S(XMM_REG), S(XMM_OR_MEM), S(NONE), 0),
},
[0x03] = {
  .base = V(M(PHADDSW), 2, S(MM_REG), S(MM_OR_MEM), S(NONE), 0),
  .variant_66 = V(M(PHADDSW), 2, S(XMM_REG), S(XMM_OR_MEM), S(NONE), 0),
},
[0x04] = {
  .base = V(M(PMADDUBSW), 2, S(MM_REG), S(MM_OR_MEM), S(NONE), 0),
  .variant_66 = V(M(PMADDUBSW), 2, S(XMM_REG), S(XMM_OR_MEM), S(NONE), 0),
},
[0x05] = {
  .base = V(M(PHSUBW), 2, S(MM_REG), S(MM_OR_MEM), S(NONE), 0),
  .variant_66 = V(M(PHSUBW), 2, S(XMM_REG), S(XMM_OR_MEM), S(NONE), 0),
},
[0x06] = {
  .base = V(M(PHSUBD), 2, S(MM_REG), S(MM_OR_MEM), S(NONE), 0),
  .variant_66 = V(M(PHSUBD), 2, S(XMM_REG), S(XMM_OR_MEM), S(NONE), 0),
},
[0x07] = {
  .base = V(M(PHSUBSW), 2, S(MM_REG), S(MM_OR_MEM), S(NONE), 0),
  .variant_66 = V(M(PHSUBSW), 2, S(XMM_REG), S(XMM_OR_MEM), S(NONE), 0),
},
[0x08] = {
  .base = V(M(PSIGNB), 2, S(MM_REG), S(MM_OR_MEM), S(NONE), 0),
  .variant_66 = V(M(PSIGNB), 2, S(XMM_REG), S(XMM_OR_MEM), S(NONE), 0),
},
[0x09] = {
  .base = V(M(PSIGNW), 2, S(MM_REG), S(MM_OR_MEM), S(NONE), 0),
  .variant_66 = V(M(PSIGNW), 2, S(XMM_REG), S(XMM_OR_MEM), S(NONE), 0),
},
[0x0A] = {
  .base = V(M(PSIGND), 2, S(MM_REG), S(MM_OR_MEM), S(NONE), 0),
  .variant_66 = V(M(PSIGND), 2, S(XMM_REG), S(XMM_OR_MEM), S(NONE), 0),
},
[0x0B] = {
  .base = V(M(PMULHRSW), 2, S(MM_REG), S(MM_OR_MEM), S(NONE), 0),
  .variant_66 = V(M(PMULHRSW), 2, S(XMM_REG), S(XMM_OR_MEM), S(NONE), 0),
},
[0x10] = {
  .variant_66 = V(M(PBLENDVB), 3, S(XMM_REG), S(XMM_OR_MEM), S(IMPLICIT_GPR), 0),
},
[0x14] = {
  .variant_66 = V(M(BLENDVPS), 3, S(XMM_REG), S(XMM_OR_MEM), S(IMPLICIT_GPR), 0),
},
[0x15] = {
  .variant_66 = V(M(BLENDVPD), 3, S(XMM_REG), S(XMM_OR_MEM), S(IMPLICIT_GPR), 0),
},
[0x17] = {
  .variant_66 = V(M(PTEST), 2, S(XMM_REG), S(XMM_OR_MEM), S(NONE), 0),
},
[0x1C] = {
  .variant_66 = V(M(PABSB), 2, S(XMM_REG), S(XMM_OR_MEM), S(NONE), 0),
},
[0x1D] = {
  .variant_66 = V(M(PABSW), 2, S(XMM_REG), S(XMM_OR_MEM), S(NONE), 0),
},
[0x1E] = {
  .variant_66 = V(M(PABSD), 2, S(XMM_REG), S(XMM_OR_MEM), S(NONE), 0),
},
[0x20] = {
  .variant_66 = V(M(PMOVSXBW), 2, S(XMM_REG), S(XMM_OR_MEM), S(NONE), 64),
},
[0x21] = {
  .variant_66 = V(M(PMOVSXBD), 2, S(XMM_REG), S(XMM_OR_MEM), S(NONE), 32),
},
[0x22] = {
  .variant_66 = V(M(PMOVSXBQ), 2, S(XMM_REG), S(XMM_OR_MEM), S(NONE), 16),
},
[0x23] = {
  .variant_66 = V(M(PMOVSXWD), 2, S(XMM_REG), S(XMM_OR_MEM), S(NONE), 32),
},
[0x24] = {
  .variant_66 = V(M(PMOVSXWQ), 2, S(XMM_REG), S(XMM_OR_MEM), S(NONE), 16),
},
[0x25] = {
  .variant_66 = V(M(PMOVSXDQ), 2, S(XMM_REG), S(XMM_OR_MEM), S(NONE), 32),
},
[0x28] = {
  .variant_66 = V(M(PMULDQ), 2, S(XMM_REG), S(XMM_OR_MEM), S(NONE), 0),
},
[0x29] = {
  .variant_66 = V(M(PCMPEQQ), 2, S(XMM_REG), S(XMM_OR_MEM), S(NONE), 0),
},
[0x2A] = {
  .variant_66 = V(M(MOVNTDQA), 2, S(XMM_REG), S(XMM_OR_MEM), S(NONE), 0),
},
[0x2B] = {
  .variant_66 = V(M(PACKUSDW), 2, S(XMM_REG), S(XMM_OR_MEM), S(NONE), 0),
},
[0x30] = {
  .variant_66 = V(M(PMOVZXBW), 2, S(XMM_REG), S(XMM_OR_MEM), S(NONE), 64),
},
[0x31] = {
  .variant_66 = V(M(PMOVZXBD), 2, S(XMM_REG), S(XMM_OR_MEM), S(NONE), 32),
},
[0x32] = {
  .variant_66 = V(M(PMOVZXBQ), 2, S(XMM_REG), S(XMM_OR_MEM), S(NONE), 16),
},
[0x33] = {
  .variant_66 = V(M(PMOVZXWD), 2, S(XMM_REG), S(XMM_OR_MEM), S(NONE), 32),
},
[0x34] = {
  .variant_66 = V(M(PMOVZXWQ), 2, S(XMM_REG), S(XMM_OR_MEM), S(NONE), 16),
},
[0x35] = {
  .variant_66 = V(M(PMOVZXDQ), 2, S(XMM_REG), S(XMM_OR_MEM), S(NONE), 32),
},
[0x37] = {
  .variant_66 = V(M(PCMPGTQ), 2, S(XMM_REG), S(XMM_OR_MEM), S(NONE), 0),
},
[0x3C] = {
  .variant_66 = V(M(PMAXSB), 2, S(XMM_REG), S(XMM_OR_MEM), S(NONE), 0),
},
[0x3D] = {
  .variant_66 = V(M(PMAXSD), 2, S(XMM_REG), S(XMM_OR_MEM), S(NONE), 0),
},
[0x3E] = {
  .variant_66 = V(M(PMAXUD), 2, S(XMM_REG), S(XMM_OR_MEM), S(NONE), 0),
},
[0x3F] = {
  .variant_66 = V(M(PMAXUW), 2, S(XMM_REG), S(XMM_OR_MEM), S(NONE), 0),
},
[0x40] = {
  .variant_66 = V(M(PMULLD), 2, S(XMM_REG), S(XMM_OR_MEM), S(NONE), 0),
},
[0x41] = {
  .variant_66 = V(M(PHMINPOSUW), 2, S(XMM_REG), S(XMM_OR_MEM), S(NONE), 0),
},
};
