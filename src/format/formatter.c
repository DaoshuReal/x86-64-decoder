#include "format/formatter.h"

#include <stdio.h>

#include "core/mnemonic.h"
#include "core/register.h"

#define MN(x) X86DEC_MNEMONIC_##x
#define RG(x) X86DEC_REG_##x

static const char* const x86dec_mnemonic_texts[X86DEC_MNEMONIC_COUNT] = {
  [MN(INVALID)] = "invalid",
  [MN(NOP)] = "nop",
  [MN(PAUSE)] = "pause",
  [MN(MOV)] = "mov",
  [MN(MOVSX)] = "movsx",
  [MN(MOVSXD)] = "movsxd",
  [MN(MOVZX)] = "movzx",
  [MN(LEA)] = "lea",
  [MN(XCHG)] = "xchg",
  [MN(BSWAP)] = "bswap",
  [MN(XADD)] = "xadd",
  [MN(CMPXCHG)] = "cmpxchg",
  [MN(CMPXCHG8B)] = "cmpxchg8b",
  [MN(CMPXCHG16B)] = "cmpxchg16b",
  [MN(ADD)] = "add",
  [MN(OR)] = "or",
  [MN(ADC)] = "adc",
  [MN(SBB)] = "sbb",
  [MN(AND)] = "and",
  [MN(SUB)] = "sub",
  [MN(XOR)] = "xor",
  [MN(CMP)] = "cmp",
  [MN(TEST)] = "test",
  [MN(INC)] = "inc",
  [MN(DEC)] = "dec",
  [MN(NEG)] = "neg",
  [MN(NOT)] = "not",
  [MN(MUL)] = "mul",
  [MN(IMUL)] = "imul",
  [MN(DIV)] = "div",
  [MN(IDIV)] = "idiv",
  [MN(SHL)] = "shl",
  [MN(SAL)] = "sal",
  [MN(SHR)] = "shr",
  [MN(SAR)] = "sar",
  [MN(ROL)] = "rol",
  [MN(ROR)] = "ror",
  [MN(RCL)] = "rcl",
  [MN(RCR)] = "rcr",
  [MN(SHLD)] = "shld",
  [MN(SHRD)] = "shrd",
  [MN(BT)] = "bt",
  [MN(BTS)] = "bts",
  [MN(BTR)] = "btr",
  [MN(BTC)] = "btc",
  [MN(BSF)] = "bsf",
  [MN(BSR)] = "bsr",
  [MN(TZCNT)] = "tzcnt",
  [MN(LZCNT)] = "lzcnt",
  [MN(PUSH)] = "push",
  [MN(POP)] = "pop",
  [MN(PUSHF)] = "pushf",
  [MN(POPF)] = "popf",
  [MN(CALL)] = "call",
  [MN(RET)] = "ret",
  [MN(RETF)] = "retf",
  [MN(JMP)] = "jmp",
  [MN(JO)] = "jo",
  [MN(JNO)] = "jno",
  [MN(JB)] = "jb",
  [MN(JNB)] = "jnb",
  [MN(JZ)] = "jz",
  [MN(JNZ)] = "jnz",
  [MN(JBE)] = "jbe",
  [MN(JA)] = "ja",
  [MN(JS)] = "js",
  [MN(JNS)] = "jns",
  [MN(JP)] = "jp",
  [MN(JNP)] = "jnp",
  [MN(JL)] = "jl",
  [MN(JNL)] = "jnl",
  [MN(JLE)] = "jle",
  [MN(JG)] = "jg",
  [MN(LOOP)] = "loop",
  [MN(LOOPE)] = "loope",
  [MN(LOOPNE)] = "loopne",
  [MN(JCXZ)] = "jcxz",
  [MN(JECXZ)] = "jecxz",
  [MN(JRCXZ)] = "jrcxz",
  [MN(SETO)] = "seto",
  [MN(SETNO)] = "setno",
  [MN(SETB)] = "setb",
  [MN(SETNB)] = "setnb",
  [MN(SETZ)] = "setz",
  [MN(SETNZ)] = "setnz",
  [MN(SETBE)] = "setbe",
  [MN(SETA)] = "seta",
  [MN(SETS)] = "sets",
  [MN(SETNS)] = "setns",
  [MN(SETP)] = "setp",
  [MN(SETNP)] = "setnp",
  [MN(SETL)] = "setl",
  [MN(SETNL)] = "setnl",
  [MN(SETLE)] = "setle",
  [MN(SETG)] = "setg",
  [MN(CMOVO)] = "cmovo",
  [MN(CMOVNO)] = "cmovno",
  [MN(CMOVB)] = "cmovb",
  [MN(CMOVNB)] = "cmovnb",
  [MN(CMOVZ)] = "cmovz",
  [MN(CMOVNZ)] = "cmovnz",
  [MN(CMOVBE)] = "cmovbe",
  [MN(CMOVA)] = "cmova",
  [MN(CMOVS)] = "cmovs",
  [MN(CMOVNS)] = "cmovns",
  [MN(CMOVP)] = "cmovp",
  [MN(CMOVNP)] = "cmovnp",
  [MN(CMOVL)] = "cmovl",
  [MN(CMOVNL)] = "cmovnl",
  [MN(CMOVLE)] = "cmovle",
  [MN(CMOVG)] = "cmovg",
  [MN(INT)] = "int",
  [MN(INT1)] = "int1",
  [MN(INT3)] = "int3",
  [MN(INTO)] = "into",
  [MN(IRET)] = "iret",
  [MN(IRETD)] = "iretd",
  [MN(IRETQ)] = "iretq",
  [MN(HLT)] = "hlt",
  [MN(CMC)] = "cmc",
  [MN(CLC)] = "clc",
  [MN(STC)] = "stc",
  [MN(CLI)] = "cli",
  [MN(STI)] = "sti",
  [MN(CLD)] = "cld",
  [MN(STD)] = "std",
  [MN(LEAVE)] = "leave",
  [MN(ENTER)] = "enter",
  [MN(XLAT)] = "xlat",
  [MN(CBW)] = "cbw",
  [MN(CWDE)] = "cwde",
  [MN(CDQE)] = "cdqe",
  [MN(CWD)] = "cwd",
  [MN(CDQ)] = "cdq",
  [MN(CQO)] = "cqo",
  [MN(SAHF)] = "sahf",
  [MN(LAHF)] = "lahf",
  [MN(MOVSB)] = "movsb",
  [MN(MOVSW)] = "movsw",
  [MN(MOVSD)] = "movsd",
  [MN(MOVSQ)] = "movsq",
  [MN(CMPSB)] = "cmpsb",
  [MN(CMPSW)] = "cmpsw",
  [MN(CMPSD)] = "cmpsd",
  [MN(CMPSQ)] = "cmpsq",
  [MN(STOSB)] = "stosb",
  [MN(STOSW)] = "stosw",
  [MN(STOSD)] = "stosd",
  [MN(STOSQ)] = "stosq",
  [MN(LODSB)] = "lodsb",
  [MN(LODSW)] = "lodsw",
  [MN(LODSD)] = "lodsd",
  [MN(LODSQ)] = "lodsq",
  [MN(SCASB)] = "scasb",
  [MN(SCASW)] = "scasw",
  [MN(SCASD)] = "scasd",
  [MN(SCASQ)] = "scasq",
  [MN(IN)] = "in",
  [MN(OUT)] = "out",
  [MN(EMMS)] = "emms",
  [MN(CPUID)] = "cpuid",
  [MN(RDTSC)] = "rdtsc",
  [MN(RDTSCP)] = "rdtscp",
  [MN(RDRAND)] = "rdrand",
  [MN(RDSEED)] = "rdseed",
  [MN(RDPID)] = "rdpid",
  [MN(SYSCALL)] = "syscall",
  [MN(SYSRET)] = "sysret",
  [MN(SYSENTER)] = "sysenter",
  [MN(SYSEXIT)] = "sysexit",
  [MN(SWAPGS)] = "swapgs",
  [MN(RDMSR)] = "rdmsr",
  [MN(WRMSR)] = "wrmsr",
  [MN(RDPMC)] = "rdpmc",
  [MN(CLTS)] = "clts",
  [MN(INVD)] = "invd",
  [MN(WBINVD)] = "wbinvd",
  [MN(UD0)] = "ud0",
  [MN(UD1)] = "ud1",
  [MN(UD2)] = "ud2",
  [MN(SGDT)] = "sgdt",
  [MN(SIDT)] = "sidt",
  [MN(LGDT)] = "lgdt",
  [MN(LIDT)] = "lidt",
  [MN(SMSW)] = "smsw",
  [MN(LMSW)] = "lmsw",
  [MN(INVLPG)] = "invlpg",
  [MN(SLDT)] = "sldt",
  [MN(STR)] = "str",
  [MN(LLDT)] = "lldt",
  [MN(LTR)] = "ltr",
  [MN(VERR)] = "verr",
  [MN(VERW)] = "verw",
  [MN(FXSAVE)] = "fxsave",
  [MN(FXRSTOR)] = "fxrstor",
  [MN(LDMXCSR)] = "ldmxcsr",
  [MN(STMXCSR)] = "stmxcsr",
  [MN(XSAVE)] = "xsave",
  [MN(XRSTOR)] = "xrstor",
  [MN(XSAVEOPT)] = "xsaveopt",
  [MN(CLFLUSH)] = "clflush",
  [MN(LFENCE)] = "lfence",
  [MN(MFENCE)] = "mfence",
  [MN(SFENCE)] = "sfence",
  [MN(PREFETCHNTA)] = "prefetchnta",
  [MN(PREFETCHT0)] = "prefetcht0",
  [MN(PREFETCHT1)] = "prefetcht1",
  [MN(PREFETCHT2)] = "prefetcht2",
  [MN(VMCALL)] = "vmcall",
  [MN(VMLAUNCH)] = "vmlaunch",
  [MN(VMRESUME)] = "vmresume",
  [MN(VMXOFF)] = "vmxoff",
  [MN(MONITOR)] = "monitor",
  [MN(MWAIT)] = "mwait",
  [MN(XGETBV)] = "xgetbv",
  [MN(XSETBV)] = "xsetbv",
  [MN(VMFUNC)] = "vmfunc",
  [MN(LFS)] = "lfs",
  [MN(LGS)] = "lgs",
  [MN(LSS)] = "lss",
  [MN(LAR)] = "lar",
  [MN(LSL)] = "lsl",
  [MN(VMREAD)] = "vmread",
  [MN(VMWRITE)] = "vmwrite",
  [MN(GETSEC)] = "getsec",
  [MN(POPCNT)] = "popcnt",
  [MN(ENDBR64)] = "endbr64",
  [MN(ENDBR32)] = "endbr32",
  [MN(WAIT)] = "wait",
  [MN(PUSHA)] = "pusha",
  [MN(PUSHAD)] = "pushad",
  [MN(POPA)] = "popa",
  [MN(POPAD)] = "popad",
  [MN(INSB)] = "insb",
  [MN(INSW)] = "insw",
  [MN(INSD)] = "insd",
  [MN(INSQ)] = "insq",
  [MN(OUTSB)] = "outsb",
  [MN(OUTSW)] = "outsw",
  [MN(OUTSD)] = "outsd",
  [MN(OUTSQ)] = "outsq",
  [MN(AAA)] = "aaa",
  [MN(AAS)] = "aas",
  [MN(DAA)] = "daa",
  [MN(DAS)] = "das",
  [MN(BOUND)] = "bound",
  [MN(ARPL)] = "arpl",
  [MN(LES)] = "les",
  [MN(LDS)] = "lds",
  [MN(AAM)] = "aam",
  [MN(AAD)] = "aad",
  [MN(SALC)] = "salc"
};

static const char* const x86dec_register_texts[X86DEC_REG_COUNT] = {
  [RG(NONE)] = "none",
  [RG(RAX)] = "rax",
  [RG(RCX)] = "rcx",
  [RG(RDX)] = "rdx",
  [RG(RBX)] = "rbx",
  [RG(RSP)] = "rsp",
  [RG(RBP)] = "rbp",
  [RG(RSI)] = "rsi",
  [RG(RDI)] = "rdi",
  [RG(R8)] = "r8",
  [RG(R9)] = "r9",
  [RG(R10)] = "r10",
  [RG(R11)] = "r11",
  [RG(R12)] = "r12",
  [RG(R13)] = "r13",
  [RG(R14)] = "r14",
  [RG(R15)] = "r15",
  [RG(EAX)] = "eax",
  [RG(ECX)] = "ecx",
  [RG(EDX)] = "edx",
  [RG(EBX)] = "ebx",
  [RG(ESP)] = "esp",
  [RG(EBP)] = "ebp",
  [RG(ESI)] = "esi",
  [RG(EDI)] = "edi",
  [RG(R8D)] = "r8d",
  [RG(R9D)] = "r9d",
  [RG(R10D)] = "r10d",
  [RG(R11D)] = "r11d",
  [RG(R12D)] = "r12d",
  [RG(R13D)] = "r13d",
  [RG(R14D)] = "r14d",
  [RG(R15D)] = "r15d",
  [RG(AX)] = "ax",
  [RG(CX)] = "cx",
  [RG(DX)] = "dx",
  [RG(BX)] = "bx",
  [RG(SP)] = "sp",
  [RG(BP)] = "bp",
  [RG(SI)] = "si",
  [RG(DI)] = "di",
  [RG(R8W)] = "r8w",
  [RG(R9W)] = "r9w",
  [RG(R10W)] = "r10w",
  [RG(R11W)] = "r11w",
  [RG(R12W)] = "r12w",
  [RG(R13W)] = "r13w",
  [RG(R14W)] = "r14w",
  [RG(R15W)] = "r15w",
  [RG(AL)] = "al",
  [RG(CL)] = "cl",
  [RG(DL)] = "dl",
  [RG(BL)] = "bl",
  [RG(SPL)] = "spl",
  [RG(BPL)] = "bpl",
  [RG(SIL)] = "sil",
  [RG(DIL)] = "dil",
  [RG(R8B)] = "r8b",
  [RG(R9B)] = "r9b",
  [RG(R10B)] = "r10b",
  [RG(R11B)] = "r11b",
  [RG(R12B)] = "r12b",
  [RG(R13B)] = "r13b",
  [RG(R14B)] = "r14b",
  [RG(R15B)] = "r15b",
  [RG(AH)] = "ah",
  [RG(CH)] = "ch",
  [RG(DH)] = "dh",
  [RG(BH)] = "bh",
  [RG(IP)] = "ip",
  [RG(EIP)] = "eip",
  [RG(RIP)] = "rip",
  [RG(ES)] = "es",
  [RG(CS)] = "cs",
  [RG(SS)] = "ss",
  [RG(DS)] = "ds",
  [RG(FS)] = "fs",
  [RG(GS)] = "gs",
  [RG(CR0)] = "cr0",
  [RG(CR1)] = "cr1",
  [RG(CR2)] = "cr2",
  [RG(CR3)] = "cr3",
  [RG(CR4)] = "cr4",
  [RG(CR5)] = "cr5",
  [RG(CR6)] = "cr6",
  [RG(CR7)] = "cr7",
  [RG(CR8)] = "cr8",
  [RG(CR9)] = "cr9",
  [RG(CR10)] = "cr10",
  [RG(CR11)] = "cr11",
  [RG(CR12)] = "cr12",
  [RG(CR13)] = "cr13",
  [RG(CR14)] = "cr14",
  [RG(CR15)] = "cr15",
  [RG(DR0)] = "dr0",
  [RG(DR1)] = "dr1",
  [RG(DR2)] = "dr2",
  [RG(DR3)] = "dr3",
  [RG(DR4)] = "dr4",
  [RG(DR5)] = "dr5",
  [RG(DR6)] = "dr6",
  [RG(DR7)] = "dr7"
};

const char* x86dec_mnemonic_text(enum x86dec_mnemonic_e mnemonic)
{
  if ((unsigned)mnemonic >= X86DEC_MNEMONIC_COUNT) {
    return "invalid";
  }
  return x86dec_mnemonic_texts[mnemonic];
}

const char* x86dec_register_text(enum x86dec_register_e reg)
{
  if ((unsigned)reg >= X86DEC_REG_COUNT) {
    return "none";
  }
  return x86dec_register_texts[reg];
}

bool x86dec_format_insn(const X86decInsn* insn,
    const X86decOperand* operands, char* buffer, size_t size)
{
  char* p = buffer;
  size_t left = size;
  int n;
  uint8_t i;
  if (!insn || !buffer || !size) {
    return false;
  }
#define X86DEC_EMIT(...) do { n = snprintf(p, left, __VA_ARGS__); \
    if (n < 0 || (size_t)n >= left) { return false; } \
    p += n; left -= (size_t)n; } while (0)
  if (insn->flags & X86DEC_INSN_HAS_LOCK) {
    X86DEC_EMIT("lock ");
  }
  if ((insn->flags & X86DEC_INSN_HAS_REP) &&
      insn->mnemonic != X86DEC_MNEMONIC_PAUSE) {
    X86DEC_EMIT("rep ");
  }
  if (insn->flags & X86DEC_INSN_HAS_REPNE) {
    X86DEC_EMIT("repne ");
  }
  X86DEC_EMIT("%s", x86dec_mnemonic_text(insn->mnemonic));
  if (operands) {
    for (i = 0; i < insn->operand_count; i++) {
      const X86decOperand* op = &operands[i];
      X86DEC_EMIT(i ? ", " : " ");
      switch (op->type) {
        case X86DEC_OPERAND_REG:
          X86DEC_EMIT("%s", x86dec_register_text(op->reg));
          break;
        case X86DEC_OPERAND_IMM:
          X86DEC_EMIT("0x%llx", (unsigned long long)op->imm.value);
          break;
        case X86DEC_OPERAND_MEM: {
          const char* sz = 0;
          unsigned long long mag;
          int first = 1;
          switch (op->size) {
            case 8:
              sz = "byte ptr ";
              break;
            case 16:
              sz = "word ptr ";
              break;
            case 32:
              sz = "dword ptr ";
              break;
            case 64:
              sz = "qword ptr ";
              break;
            default:
              break;
          }
          if (sz) {
            X86DEC_EMIT("%s", sz);
          }
          if (op->mem.segment != X86DEC_REG_NONE) {
            X86DEC_EMIT("%s:", x86dec_register_text(op->mem.segment));
          }
          X86DEC_EMIT("[");
          if (op->mem.base != X86DEC_REG_NONE) {
            X86DEC_EMIT("%s", x86dec_register_text(op->mem.base));
            first = 0;
          }
          if (op->mem.index != X86DEC_REG_NONE) {
            X86DEC_EMIT(first ? "%s" : "+%s",
                x86dec_register_text(op->mem.index));
            if (op->mem.scale > 1) {
              X86DEC_EMIT("*%u", op->mem.scale);
            }
            first = 0;
          }
          mag = op->mem.disp < 0
              ? 0ULL - (unsigned long long)op->mem.disp
              : (unsigned long long)op->mem.disp;
          if (op->mem.has_disp || first) {
            if (first) {
              X86DEC_EMIT(op->mem.disp < 0 ? "-0x%llx" : "0x%llx", mag);
            } else {
              X86DEC_EMIT(op->mem.disp < 0 ? "-0x%llx" : "+0x%llx", mag);
            }
          }
          X86DEC_EMIT("]");
          break;
        }
        default:
          X86DEC_EMIT("?");
          break;
      }
    }
  }
  return true;
#undef X86DEC_EMIT
}
