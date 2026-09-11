#include "tables.h"

#define M(x) X86DEC_MNEMONIC_##x
#define S(x) X86DEC_SHAPE_##x
#define V(mn, c, s0, s1, s2, mb) {(mn), (c), {(s0), (s1), (s2)}, (mb)}
#define NOVAR {0, 0, {0, 0, 0}, 0}

const X86decSseEntry x86dec_sse_mov[256] = {
[0x10] = {
  .base = V(M(MOVUPS), 2, S(XMM_REG), S(XMM_OR_MEM), S(NONE), 0),
  .variant_66 = V(M(MOVUPD), 2, S(XMM_REG), S(XMM_OR_MEM), S(NONE), 0),
  .variant_f3 = V(M(MOVSS), 2, S(XMM_REG), S(XMM_OR_MEM), S(NONE), 32),
  .variant_f2 = V(M(MOVSD_SSE), 2, S(XMM_REG), S(XMM_OR_MEM), S(NONE), 64),
},
[0x11] = {
  .base = V(M(MOVUPS), 2, S(XMM_OR_MEM), S(XMM_REG), S(NONE), 0),
  .variant_66 = V(M(MOVUPD), 2, S(XMM_OR_MEM), S(XMM_REG), S(NONE), 0),
  .variant_f3 = V(M(MOVSS), 2, S(XMM_OR_MEM), S(XMM_REG), S(NONE), 32),
  .variant_f2 = V(M(MOVSD_SSE), 2, S(XMM_OR_MEM), S(XMM_REG), S(NONE), 64),
},
[0x12] = {
  .base = V(M(MOVLPS), 2, S(XMM_REG), S(XMM_OR_MEM), S(NONE), 64),
  .variant_66 = V(M(MOVLPD), 2, S(XMM_REG), S(XMM_OR_MEM), S(NONE), 64),
  .variant_f3 = NOVAR,
  .variant_f2 = NOVAR,
},
[0x13] = {
  .base = V(M(MOVLPS), 2, S(XMM_OR_MEM), S(XMM_REG), S(NONE), 64),
  .variant_66 = V(M(MOVLPD), 2, S(XMM_OR_MEM), S(XMM_REG), S(NONE), 64),
  .variant_f3 = NOVAR,
  .variant_f2 = NOVAR,
},
[0x16] = {
  .base = V(M(MOVHPS), 2, S(XMM_REG), S(XMM_OR_MEM), S(NONE), 64),
  .variant_66 = V(M(MOVHPD), 2, S(XMM_REG), S(XMM_OR_MEM), S(NONE), 64),
  .variant_f3 = NOVAR,
  .variant_f2 = NOVAR,
},
[0x17] = {
  .base = V(M(MOVHPS), 2, S(XMM_OR_MEM), S(XMM_REG), S(NONE), 64),
  .variant_66 = V(M(MOVHPD), 2, S(XMM_OR_MEM), S(XMM_REG), S(NONE), 64),
  .variant_f3 = NOVAR,
  .variant_f2 = NOVAR,
},
[0x28] = {
  .base = V(M(MOVAPS), 2, S(XMM_REG), S(XMM_OR_MEM), S(NONE), 0),
  .variant_66 = V(M(MOVAPD), 2, S(XMM_REG), S(XMM_OR_MEM), S(NONE), 0),
  .variant_f3 = NOVAR,
  .variant_f2 = NOVAR,
},
[0x29] = {
  .base = V(M(MOVAPS), 2, S(XMM_OR_MEM), S(XMM_REG), S(NONE), 0),
  .variant_66 = V(M(MOVAPD), 2, S(XMM_OR_MEM), S(XMM_REG), S(NONE), 0),
  .variant_f3 = NOVAR,
  .variant_f2 = NOVAR,
},
[0x2B] = {
  .base = V(M(MOVNTPS), 2, S(XMM_OR_MEM), S(XMM_REG), S(NONE), 0),
  .variant_66 = V(M(MOVNTPD), 2, S(XMM_OR_MEM), S(XMM_REG), S(NONE), 0),
  .variant_f3 = NOVAR,
  .variant_f2 = NOVAR,
},
[0x50] = {
  .base = V(M(MOVMSKPS), 2, S(R32_REG), S(XMM_RM), S(NONE), 0),
  .variant_66 = V(M(MOVMSKPD), 2, S(R32_REG), S(XMM_RM), S(NONE), 0),
  .variant_f3 = NOVAR,
  .variant_f2 = NOVAR,
},
[0x6E] = {
  .base = V(M(MOVD), 2, S(XMM_REG), S(R32_OR_MEM), S(NONE), 0),
  .variant_66 = V(M(MOVQ), 2, S(XMM_REG), S(GPR_OR_MEM), S(NONE), 64),
  .variant_f3 = NOVAR,
  .variant_f2 = NOVAR,
},
[0x6F] = {
  .base = V(M(MOVQ), 2, S(MM_REG), S(MM_OR_MEM), S(NONE), 0),
  .variant_66 = V(M(MOVDQA), 2, S(XMM_REG), S(XMM_OR_MEM), S(NONE), 0),
  .variant_f3 = V(M(MOVDQU), 2, S(XMM_REG), S(XMM_OR_MEM), S(NONE), 0),
  .variant_f2 = NOVAR,
},
[0x7E] = {
  .base = V(M(MOVD), 2, S(R32_OR_MEM), S(XMM_REG), S(NONE), 0),
  .variant_66 = V(M(MOVQ), 2, S(GPR_OR_MEM), S(XMM_REG), S(NONE), 64),
  .variant_f3 = NOVAR,
  .variant_f2 = NOVAR,
},
[0x7F] = {
  .base = V(M(MOVQ), 2, S(MM_OR_MEM), S(MM_REG), S(NONE), 0),
  .variant_66 = V(M(MOVDQA), 2, S(XMM_OR_MEM), S(XMM_REG), S(NONE), 0),
  .variant_f3 = V(M(MOVDQU), 2, S(XMM_OR_MEM), S(XMM_REG), S(NONE), 0),
  .variant_f2 = NOVAR,
},
[0xC3] = {
  .base = V(M(MOVNTI), 2, S(GPR_OR_MEM), S(GPR_REG), S(NONE), 0),
  .variant_66 = NOVAR,
  .variant_f3 = NOVAR,
  .variant_f2 = NOVAR,
},
[0xD6] = {
  .base = NOVAR,
  .variant_66 = NOVAR,
  .variant_f3 = V(M(MOVQ2DQ), 2, S(XMM_REG), S(XMM_RM), S(NONE), 0),
  .variant_f2 = V(M(MOVDQ2Q), 2, S(XMM_REG), S(XMM_RM), S(NONE), 0),
},
[0xD7] = {
  .base = V(M(PMOVMSKB), 2, S(R32_REG), S(MM_OR_MEM), S(NONE), 0),
  .variant_66 = V(M(PMOVMSKB), 2, S(R32_REG), S(XMM_OR_MEM), S(NONE), 0),
  .variant_f3 = NOVAR,
  .variant_f2 = NOVAR,
},
[0xE7] = {
  .base = V(M(MOVNTQ), 2, S(MM_OR_MEM), S(MM_REG), S(NONE), 0),
  .variant_66 = V(M(MOVNTDQ), 2, S(XMM_OR_MEM), S(XMM_REG), S(NONE), 0),
  .variant_f3 = NOVAR,
  .variant_f2 = NOVAR,
},
[0xF0] = {
  .base = NOVAR,
  .variant_66 = NOVAR,
  .variant_f3 = NOVAR,
  .variant_f2 = V(M(LDDQU), 2, S(XMM_REG), S(XMM_OR_MEM), S(NONE), 0),
},
[0xF7] = {
  .base = V(M(MASKMOVQ), 0, S(NONE), S(NONE), S(NONE), 0),
  .variant_66 = V(M(MASKMOVDQU), 0, S(NONE), S(NONE), S(NONE), 0),
  .variant_f3 = NOVAR,
  .variant_f2 = NOVAR,
}
};
