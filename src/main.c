#include <stdio.h>
#include <string.h>

#include <Windows.h>

#include "x86dec.h"

#include "test/vectors.h"

#define MN(x) X86DEC_MNEMONIC_##x

static const Vec x86dec_vectors[] = {
  {"\x90", 1, 0, X86DEC_OK, MN(NOP), 1, "nop"},
  {"\xC3", 1, 0, X86DEC_OK, MN(RET), 1, "ret"},
  {"\x55", 1, 0, X86DEC_OK, MN(PUSH), 1, "push rbp"},
  {"\x5D", 1, 0, X86DEC_OK, MN(POP), 1, "pop rbp"},
  {"\x50", 1, 0, X86DEC_OK, MN(PUSH), 1, "push rax"},
  {"\x58", 1, 0, X86DEC_OK, MN(POP), 1, "pop rax"},
  {"\x48\x89\xE5", 3, 0, X86DEC_OK, MN(MOV), 3, "mov rbp, rsp"},
  {"\x48\x83\xEC\x28", 4, 0, X86DEC_OK, MN(SUB), 4, "sub rsp, 0x28"},
  {"\xB8\x34\x12\x00\x00", 5, 0, X86DEC_OK, MN(MOV), 5, "mov eax, 0x1234"},
  {"\x48\xB8\x78\x56\x34\x12\x00\x00\x00\x00", 10, 0, X86DEC_OK, MN(MOV), 10,
      "mov rax, 0x12345678"},
  {"\xE8\x00\x00\x00\x00", 5, 0, X86DEC_OK, MN(CALL), 5, "call 0x0"},
  {"\xEB\xFE", 2, 0, X86DEC_OK, MN(JMP), 2, "jmp 0xfffffffffffffffe"},
  {"\x74\x05", 2, 0, X86DEC_OK, MN(JZ), 2, "jz 0x5"},
  {"\x0F\x84\x10\x00\x00\x00", 6, 0, X86DEC_OK, MN(JZ), 6, "jz 0x10"},
  {"\x31\xC0", 2, 0, X86DEC_OK, MN(XOR), 2, "xor eax, eax"},
  {"\x48\x31\xD2", 3, 0, X86DEC_OK, MN(XOR), 3, "xor rdx, rdx"},
  {"\x8D\x44\x24\x10", 4, 0, X86DEC_OK, MN(LEA), 4,
      "lea eax, qword ptr ss:[rsp+0x10]"},
  {"\xC9", 1, 0, X86DEC_OK, MN(LEAVE), 1, "leave"},
  {"\x0F\x1F\x44\x00\x00", 5, 0, X86DEC_OK, MN(NOP), 5,
      "nop dword ptr ds:[rax+rax+0x0], eax"},
  {"\xF3\x90", 2, 0, X86DEC_OK, MN(PAUSE), 2, "pause"},
  {"\x0F\xA2", 2, 0, X86DEC_OK, MN(CPUID), 2, "cpuid"},
  {"\x66\x90", 2, 0, X86DEC_OK, MN(NOP), 2, "nop"},
  {"\x40\x90", 2, 0, X86DEC_OK, MN(NOP), 2, "nop"},
  {"\x41\xB8\x34\x12\x00\x00", 6, 0, X86DEC_OK, MN(MOV), 6, "mov r8d, 0x1234"},
  {"\x44\x8B\xC0", 3, 0, X86DEC_OK, MN(MOV), 3, "mov r8d, eax"},
  {"\xF4", 1, 0, X86DEC_OK, MN(HLT), 1, "hlt"},
  {"\xCC", 1, 0, X86DEC_OK, MN(INT3), 1, "int3"},
  {"\xF1", 1, 0, X86DEC_OK, MN(INT1), 1, "int1"},
  {"\xCD\x80", 2, 0, X86DEC_OK, MN(INT), 2, "int 0x80"},
  {"\xFF\xD0", 2, 0, X86DEC_OK, MN(CALL), 2, "call rax"},
  {"\xFF\xE0", 2, 0, X86DEC_OK, MN(JMP), 2, "jmp rax"},
  {"\xFF\xF0", 2, 0, X86DEC_OK, MN(PUSH), 2, "push rax"},
  {"\xFF\xC0", 2, 0, X86DEC_OK, MN(INC), 2, "inc eax"},
  {"\xFF\xC8", 2, 0, X86DEC_OK, MN(DEC), 2, "dec eax"},
  {"\xFE\xC0", 2, 0, X86DEC_OK, MN(INC), 2, "inc al"},
  {"\xFE\xC8", 2, 0, X86DEC_OK, MN(DEC), 2, "dec al"},
  {"\x6A\x00", 2, 0, X86DEC_OK, MN(PUSH), 2, "push 0x0"},
  {"\x68\x00\x10\x00\x00", 5, 0, X86DEC_OK, MN(PUSH), 5, "push 0x1000"},
  {"\x89\xD8", 2, 0, X86DEC_OK, MN(MOV), 2, "mov eax, ebx"},
  {"\x8B\x45\x08", 3, 0, X86DEC_OK, MN(MOV), 3,
      "mov eax, dword ptr ss:[rbp+0x8]"},
  {"\x48\x8B\x05\x00\x00\x00\x00", 7, 0, X86DEC_OK, MN(MOV), 7,
      "mov rax, qword ptr [rip+0x0]"},
  {"\x04\x05", 2, 0, X86DEC_OK, MN(ADD), 2, "add al, 0x5"},
  {"\x05\x00\x10\x00\x00", 5, 0, X86DEC_OK, MN(ADD), 5, "add eax, 0x1000"},
  {"\x3C\x00", 2, 0, X86DEC_OK, MN(CMP), 2, "cmp al, 0x0"},
  {"\x84\xC0", 2, 0, X86DEC_OK, MN(TEST), 2, "test al, al"},
  {"\x85\xC9", 2, 0, X86DEC_OK, MN(TEST), 2, "test ecx, ecx"},
  {"\x09\xC8", 2, 0, X86DEC_OK, MN(OR), 2, "or eax, ecx"},
  {"\x48\x09\xC8", 3, 0, X86DEC_OK, MN(OR), 3, "or rax, rcx"},
  {"\x0F\xAF\xC1", 3, 0, X86DEC_OK, MN(IMUL), 3, "imul eax, ecx"},
  {"\x0F\xB6\xC3", 3, 0, X86DEC_OK, MN(MOVZX), 3, "movzx eax, bl"},
  {"\x0F\xBE\xC0", 3, 0, X86DEC_OK, MN(MOVSX), 3, "movsx eax, al"},
  {"\x0F\xB7\xC0", 3, 0, X86DEC_OK, MN(MOVZX), 3, "movzx eax, ax"},
  {"\x0F\xBF\xC0", 3, 0, X86DEC_OK, MN(MOVSX), 3, "movsx eax, ax"},
  {"\x0F\xC8", 2, 0, X86DEC_OK, MN(BSWAP), 2, "bswap eax"},
  {"\x48\x0F\xCB", 3, 0, X86DEC_OK, MN(BSWAP), 3, "bswap rbx"},
  {"\x00\x00", 2, 0, X86DEC_OK, MN(ADD), 2, "add byte ptr ds:[rax], al"},
  {"\x0F\x0B", 2, 0, X86DEC_OK, MN(UD2), 2, "ud2"},
  {"\x0F\xB9", 2, 0, X86DEC_OK, MN(UD1), 2, "ud1"},
  {"\x0F\xFF", 2, 0, X86DEC_OK, MN(UD0), 2, "ud0"},
  {"\xF6\xC0\x01", 3, 0, X86DEC_OK, MN(TEST), 3, "test al, 0x1"},
  {"\xF7\xC7\xFF\xFF\x00\x00", 6, 0, X86DEC_OK, MN(TEST), 6, "test edi, 0xffff"},
  {"\xF7\xD8", 2, 0, X86DEC_OK, MN(NEG), 2, "neg eax"},
  {"\xF7\xE3", 2, 0, X86DEC_OK, MN(MUL), 2, "mul ebx"},
  {"\xF7\xFB", 2, 0, X86DEC_OK, MN(IDIV), 2, "idiv ebx"},
  {"\xC7\x45\xFC\x00\x00\x00\x00", 7, 0, X86DEC_OK, MN(MOV), 7,
      "mov dword ptr ss:[rbp-0x4], 0x0"},
  {"\x83\xF8\x05", 3, 0, X86DEC_OK, MN(CMP), 3, "cmp eax, 0x5"},
  {"\x80\xC8\x01", 3, 0, X86DEC_OK, MN(OR), 3, "or al, 0x1"},
  {"\xA4", 1, 0, X86DEC_OK, MN(MOVSB), 1, "movsb"},
  {"\xA5", 1, 0, X86DEC_OK, MN(MOVSD), 1, "movsd"},
  {"\x66\xA5", 2, 0, X86DEC_OK, MN(MOVSW), 2, "movsw"},
  {"\xA6", 1, 0, X86DEC_OK, MN(CMPSB), 1, "cmpsb"},
  {"\xAA", 1, 0, X86DEC_OK, MN(STOSB), 1, "stosb"},
  {"\xAC", 1, 0, X86DEC_OK, MN(LODSB), 1, "lodsb"},
  {"\xAE", 1, 0, X86DEC_OK, MN(SCASB), 1, "scasb"},
  {"\x6C", 1, 0, X86DEC_OK, MN(INSB), 1, "insb"},
  {"\x6D", 1, 0, X86DEC_OK, MN(INSD), 1, "insd"},
  {"\x6E", 1, 0, X86DEC_OK, MN(OUTSB), 1, "outsb"},
  {"\x6F", 1, 0, X86DEC_OK, MN(OUTSD), 1, "outsd"},
  {"\xE4\x60", 2, 0, X86DEC_OK, MN(IN), 2, "in al, 0x60"},
  {"\xE5\x00", 2, 0, X86DEC_OK, MN(IN), 2, "in eax, 0x0"},
  {"\xEC", 1, 0, X86DEC_OK, MN(IN), 1, "in al, dx"},
  {"\xED", 1, 0, X86DEC_OK, MN(IN), 1, "in eax, dx"},
  {"\xEE", 1, 0, X86DEC_OK, MN(OUT), 1, "out dx, al"},
  {"\xEF", 1, 0, X86DEC_OK, MN(OUT), 1, "out dx, eax"},
  {"\x9C", 1, 0, X86DEC_OK, MN(PUSHFQ), 1, "pushfq"},
  {"\x9D", 1, 0, X86DEC_OK, MN(POPFQ), 1, "popfq"},
  {"\x9E", 1, 0, X86DEC_OK, MN(SAHF), 1, "sahf"},
  {"\x9F", 1, 0, X86DEC_OK, MN(LAHF), 1, "lahf"},
  {"\xF5", 1, 0, X86DEC_OK, MN(CMC), 1, "cmc"},
  {"\xF8", 1, 0, X86DEC_OK, MN(CLC), 1, "clc"},
  {"\xF9", 1, 0, X86DEC_OK, MN(STC), 1, "stc"},
  {"\xFA", 1, 0, X86DEC_OK, MN(CLI), 1, "cli"},
  {"\xFB", 1, 0, X86DEC_OK, MN(STI), 1, "sti"},
  {"\xFC", 1, 0, X86DEC_OK, MN(CLD), 1, "cld"},
  {"\xFD", 1, 0, X86DEC_OK, MN(STD), 1, "std"},
  {"\x63\xC0", 2, 0, X86DEC_OK, MN(MOVSXD), 2, "movsxd eax, eax"},
  {"\x98", 1, 0, X86DEC_OK, MN(CWDE), 1, "cwde"},
  {"\x48\x98", 2, 0, X86DEC_OK, MN(CDQE), 2, "cdqe"},
  {"\x99", 1, 0, X86DEC_OK, MN(CDQ), 1, "cdq"},
  {"\x48\x99", 2, 0, X86DEC_OK, MN(CQO), 2, "cqo"},
  {"\x0F\xA3\xC1", 3, 0, X86DEC_OK, MN(BT), 3, "bt ecx, eax"},
  {"\x0F\xB3\xC1", 3, 0, X86DEC_OK, MN(BTR), 3, "btr ecx, eax"},
  {"\x0F\xBA\xE8\x05", 4, 0, X86DEC_OK, MN(BTS), 4, "bts eax, 0x5"},
  {"\x69\xC0\x05\x00\x00\x00", 6, 0, X86DEC_OK, MN(IMUL), 6, "imul eax, eax, 0x5"},
  {"\x6B\xC0\x05", 3, 0, X86DEC_OK, MN(IMUL), 3, "imul eax, eax, 0x5"},
  {"\x0F\xA4\xC1\x04", 4, 0, X86DEC_OK, MN(SHLD), 4, "shld ecx, eax, 0x4"},
  {"\x0F\xA5\xC1", 3, 0, X86DEC_OK, MN(SHLD), 3, "shld ecx, eax, cl"},
  {"\x0F\xAD\xC1", 3, 0, X86DEC_OK, MN(SHRD), 3, "shrd ecx, eax, cl"},
  {"\x0F\xC1\xC1", 3, 0, X86DEC_OK, MN(XADD), 3, "xadd ecx, eax"},
  {"\x0F\xB0\xC1", 3, 0, X86DEC_OK, MN(CMPXCHG), 3, "cmpxchg cl, al"},
  {"\x0F\xB1\xC8", 3, 0, X86DEC_OK, MN(CMPXCHG), 3, "cmpxchg eax, ecx"},
  {"\x0F\x20\xC0", 3, 0, X86DEC_OK, MN(MOV), 3, "mov rax, cr0"},
  {"\x0F\x22\xDB", 3, 0, X86DEC_OK, MN(MOV), 3, "mov cr3, rbx"},
  {"\x0F\x21\xC0", 3, 0, X86DEC_OK, MN(MOV), 3, "mov rax, dr0"},
  {"\x0F\x23\xDB", 3, 0, X86DEC_OK, MN(MOV), 3, "mov dr3, rbx"},
  {"\x0F\x01\xF8", 3, 0, X86DEC_OK, MN(SWAPGS), 3, "swapgs"},
  {"\x0F\x01\xF9", 3, 0, X86DEC_OK, MN(RDTSCP), 3, "rdtscp"},
  {"\x0F\x01\xC1", 3, 0, X86DEC_OK, MN(VMCALL), 3, "vmcall"},
  {"\x0F\x01\xC2", 3, 0, X86DEC_OK, MN(VMLAUNCH), 3, "vmlaunch"},
  {"\x0F\x01\xC3", 3, 0, X86DEC_OK, MN(VMRESUME), 3, "vmresume"},
  {"\x0F\x01\xC4", 3, 0, X86DEC_OK, MN(VMXOFF), 3, "vmxoff"},
  {"\x0F\x01\xC8", 3, 0, X86DEC_OK, MN(MONITOR), 3, "monitor"},
  {"\x0F\x01\xC9", 3, 0, X86DEC_OK, MN(MWAIT), 3, "mwait"},
  {"\x0F\x01\xD0", 3, 0, X86DEC_OK, MN(XGETBV), 3, "xgetbv"},
  {"\x0F\x01\xD1", 3, 0, X86DEC_OK, MN(XSETBV), 3, "xsetbv"},
  {"\x0F\x01\xD4", 3, 0, X86DEC_OK, MN(VMFUNC), 3, "vmfunc"},
  {"\x0F\xAE\xF0", 3, 0, X86DEC_OK, MN(MFENCE), 3, "mfence"},
  {"\x0F\xAE\xE8", 3, 0, X86DEC_OK, MN(LFENCE), 3, "lfence"},
  {"\x0F\xAE\xF8", 3, 0, X86DEC_OK, MN(SFENCE), 3, "sfence"},
  {"\x0F\xAE\x38", 3, 0, X86DEC_OK, MN(CLFLUSH), 3, "clflush ds:[rax]"},
  {"\x0F\xC7\xF6", 3, 0, X86DEC_OK, MN(RDRAND), 3, "rdrand esi"},
  {"\x0F\xC7\xFF", 3, 0, X86DEC_OK, MN(RDSEED), 3, "rdseed edi"},
  {"\xF3\x0F\xC7\xF8", 4, 0, X86DEC_OK, MN(RDPID), 4, "rdpid rax"},
  {"\x0F\xBC\xC1", 3, 0, X86DEC_OK, MN(BSF), 3, "bsf eax, ecx"},
  {"\xF3\x0F\xBC\xC1", 4, 0, X86DEC_OK, MN(TZCNT), 4, "tzcnt eax, ecx"},
  {"\x0F\xBD\xC1", 3, 0, X86DEC_OK, MN(BSR), 3, "bsr eax, ecx"},
  {"\xF3\x0F\xBD\xC1", 4, 0, X86DEC_OK, MN(LZCNT), 4, "lzcnt eax, ecx"},
  {"\xC8\x10\x00\x03", 4, 0, X86DEC_OK, MN(ENTER), 4, "enter 0x10, 0x3"},
  {"\xCA\x04\x00", 3, 0, X86DEC_OK, MN(RET), 3, "ret 0x4"},
  {"\xCB", 1, 0, X86DEC_OK, MN(RET), 1, "ret"},
  {"\xC2\x08\x00", 3, 0, X86DEC_OK, MN(RET), 3, "ret 0x8"},
  {"\xE0\xFE", 2, 0, X86DEC_OK, MN(LOOPNE), 2, "loopne 0xfffffffffffffffe"},
  {"\xE1\xFE", 2, 0, X86DEC_OK, MN(LOOPE), 2, "loope 0xfffffffffffffffe"},
  {"\xE2\xFE", 2, 0, X86DEC_OK, MN(LOOP), 2, "loop 0xfffffffffffffffe"},
  {"\xE3\x00", 2, 0, X86DEC_OK, MN(JRCXZ), 2, "jrcxz 0x0"},
  {"\x67\xE3\x00", 3, 0, X86DEC_OK, MN(JECXZ), 3, "jecxz 0x0"},
  {"\xD7", 1, 0, X86DEC_OK, MN(XLAT), 1, "xlat"},
  {"\x8C\xD8", 2, 0, X86DEC_OK, MN(MOV), 2, "mov eax, ds"},
  {"\x8E\xD8", 2, 0, X86DEC_OK, MN(MOV), 2, "mov ds, ax"},
  {"\xD1\xE8", 2, 0, X86DEC_OK, MN(SHR), 2, "shr eax, 0x1"},
  {"\xC1\xE0\x04", 3, 0, X86DEC_OK, MN(SHL), 3, "shl eax, 0x4"},
  {"\xC0\xF0\x06", 3, 0, X86DEC_OK, MN(SHL), 3, "shl al, 0x6"},
  {"\xD3\xE0", 2, 0, X86DEC_OK, MN(SHL), 2, "shl eax, cl"},
  {"\x70\x00", 2, 0, X86DEC_OK, MN(JO), 2, "jo 0x0"},
  {"\x7F\x00", 2, 0, X86DEC_OK, MN(JNLE), 2, "jnle 0x0"},
  {"\x0F\x8F\x00\x00\x00\x00", 6, 0, X86DEC_OK, MN(JNLE), 6, "jnle 0x0"},
  {"\x0F\x90\xC0", 3, 0, X86DEC_OK, MN(SETO), 3, "seto al"},
  {"\x0F\x95\xC0", 3, 0, X86DEC_OK, MN(SETNZ), 3, "setnz al"},
  {"\x0F\x9F\xC0", 3, 0, X86DEC_OK, MN(SETNLE), 3, "setnle al"},
  {"\x0F\x40\xC1", 3, 0, X86DEC_OK, MN(CMOVO), 3, "cmovo eax, ecx"},
  {"\x0F\x4F\xC8", 3, 0, X86DEC_OK, MN(CMOVNLE), 3, "cmovnle ecx, eax"},
  {"\x0F\x31", 2, 0, X86DEC_OK, MN(RDTSC), 2, "rdtsc"},
  {"\x0F\x05", 2, 0, X86DEC_OK, MN(SYSCALL), 2, "syscall"},
  {"\x0F\x34", 2, 0, X86DEC_OK, MN(SYSENTER), 2, "sysenter"},
  {"\x0F\x35", 2, 0, X86DEC_OK, MN(SYSEXIT), 2, "sysexit"},
  {"\x0F\x07", 2, 0, X86DEC_OK, MN(SYSRET), 2, "sysret"},
  {"\x0F\x30", 2, 0, X86DEC_OK, MN(WRMSR), 2, "wrmsr"},
  {"\x0F\x32", 2, 0, X86DEC_OK, MN(RDMSR), 2, "rdmsr"},
  {"\x0F\x33", 2, 0, X86DEC_OK, MN(RDPMC), 2, "rdpmc"},
  {"\x0F\x06", 2, 0, X86DEC_OK, MN(CLTS), 2, "clts"},
  {"\x0F\x08", 2, 0, X86DEC_OK, MN(INVD), 2, "invd"},
  {"\x0F\x09", 2, 0, X86DEC_OK, MN(WBINVD), 2, "wbinvd"},
  {"\x0F\x37", 2, 0, X86DEC_OK, MN(GETSEC), 2, "getsec"},
  {"\x9B", 1, 0, X86DEC_OK, MN(FWAIT), 1, "fwait"},
  {"\x0F\x77", 2, 0, X86DEC_OK, MN(EMMS), 2, "emms"},
  {"\x0F\x00\xC0", 3, 0, X86DEC_OK, MN(SLDT), 3, "sldt eax"},
  {"\x0F\x00\x00", 3, 0, X86DEC_OK, MN(SLDT), 3, "sldt word ptr ds:[rax]"},
  {"\x0F\x00\xC8", 3, 0, X86DEC_OK, MN(STR), 3, "str eax"},
  {"\x0F\x01\x00", 3, 0, X86DEC_OK, MN(SGDT), 3, "sgdt tbyte ptr ds:[rax]"},
  {"\x0F\x18\x00", 3, 0, X86DEC_OK, MN(PREFETCHNTA), 3,
      "prefetchnta byte ptr ds:[rax]"},
  {"\x0F\x18\x08", 3, 0, X86DEC_OK, MN(PREFETCHT0), 3,
      "prefetcht0 byte ptr ds:[rax]"},
  {"\x0F\x18\x20", 3, 0, X86DEC_OK, MN(NOP), 3, "nop dword ptr ds:[rax]"},
  {"\x0F\x1F\x00", 3, 0, X86DEC_OK, MN(NOP), 3, "nop dword ptr ds:[rax], eax"},
  {"\x48\x0F\x78\xC1", 4, 0, X86DEC_OK, MN(VMREAD), 4, "vmread rcx, rax"},
  {"\x48\x0F\x79\xC1", 4, 0, X86DEC_OK, MN(VMWRITE), 4, "vmwrite rax, rcx"},
  {"\x0F\x02\xC0", 3, 0, X86DEC_OK, MN(LAR), 3, "lar eax, eax"},
  {"\x0F\x03\xC0", 3, 0, X86DEC_OK, MN(LSL), 3, "lsl eax, eax"},
  {"\x0F\xB2\x08", 3, 0, X86DEC_OK, MN(LSS), 3, "lss ecx, fword ptr ds:[rax]"},
  {"\x0F\xB4\x08", 3, 0, X86DEC_OK, MN(LFS), 3, "lfs ecx, fword ptr ds:[rax]"},
  {"\x8D\x04\x25\x00\x10\x00\x00", 7, 0, X86DEC_OK, MN(LEA), 7,
      "lea eax, qword ptr ds:[0x1000]"},
  {"\x8B\x44\x8B\x10", 4, 0, X86DEC_OK, MN(MOV), 4,
      "mov eax, dword ptr ds:[rbx+rcx*4+0x10]"},
  {"\x48\x8B\x4C\x24\x08", 5, 0, X86DEC_OK, MN(MOV), 5,
      "mov rcx, qword ptr ss:[rsp+0x8]"},
  {"\x2E\x8B\x00", 3, 0, X86DEC_OK, MN(MOV), 3, "mov eax, dword ptr ds:[rax]"},
  {"\xF0\xFF\x00", 3, 0, X86DEC_OK, MN(INC), 3, "lock inc dword ptr ds:[rax]"},
  {"\x8F\xC0", 2, 0, X86DEC_OK, MN(POP), 2, "pop rax"},
  {"\xCF", 1, 0, X86DEC_OK, MN(IRETD), 1, "iretd"},
  {"\xA0\x00\x10\x00\x00\x00\x00\x00\x00", 9, 0, X86DEC_OK, MN(MOV), 9,
      "mov al, byte ptr ds:[0x1000]"},
  {"\x06", 1, 1, X86DEC_OK, MN(PUSH), 1, "push es"},
  {"\x60", 1, 1, X86DEC_OK, MN(PUSHAD), 1, "pushad"},
  {"\x66\x60", 2, 1, X86DEC_OK, MN(PUSHA), 2, "pusha"},
  {"\x61", 1, 1, X86DEC_OK, MN(POPAD), 1, "popad"},
  {"\xD4\x0A", 2, 1, X86DEC_OK, MN(AAM), 2, "aam 0xa"},
  {"\xD5\x0A", 2, 1, X86DEC_OK, MN(AAD), 2, "aad 0xa"},
  {"\xD6", 1, 1, X86DEC_OK, MN(SALC), 1, "salc"},
  {"\xCE", 1, 1, X86DEC_OK, MN(INTO), 1, "into"},
  {"\x62\x03", 2, 1, X86DEC_OK, MN(BOUND), 2, "bound eax, qword ptr ds:[ebx]"},
  {"\xC4\x03", 2, 1, X86DEC_OK, MN(LES), 2, "les eax, fword ptr ds:[ebx]"},
  {"\xC5\x03", 2, 1, X86DEC_OK, MN(LDS), 2, "lds eax, fword ptr ds:[ebx]"},
  {"\x63\xC0", 2, 1, X86DEC_OK, MN(ARPL), 2, "arpl ax, ax"},
  {"\x67\x8B\x00", 3, 1, X86DEC_OK, MN(MOV), 3, "mov eax, dword ptr ds:[bx+si]"},
  {"\x66\xB8\x34\x12", 4, 1, X86DEC_OK, MN(MOV), 4, "mov ax, 0x1234"},
  {"\xCF", 1, 1, X86DEC_OK, MN(IRETD), 1, "iretd"},
  {"\x66\xCF", 2, 1, X86DEC_OK, MN(IRET), 2, "iret"},
  {"\xA0\x00\x10\x00\x00", 5, 1, X86DEC_OK, MN(MOV), 5,
      "mov al, byte ptr ds:[0x1000]"},
  {"\xA1\x00\x10\x00\x00", 5, 1, X86DEC_OK, MN(MOV), 5,
      "mov eax, dword ptr ds:[0x1000]"},
  {"\xA3\x00\x10\x00\x00", 5, 1, X86DEC_OK, MN(MOV), 5,
      "mov dword ptr ds:[0x1000], eax"},
  {"\x06", 1, 0, X86DEC_INVALID, MN(INVALID), 0, 0},
  {"\x40", 1, 0, X86DEC_NEED_MORE, MN(INVALID), 0, 0},
  {"\x48", 1, 0, X86DEC_NEED_MORE, MN(INVALID), 0, 0},
  {"\x0F", 1, 0, X86DEC_NEED_MORE, MN(INVALID), 0, 0},
  {"\xFF", 1, 0, X86DEC_NEED_MORE, MN(INVALID), 0, 0},
  {"\xF6\xC0", 2, 0, X86DEC_NEED_MORE, MN(INVALID), 0, 0},
  {"\xE8\x00\x00", 3, 0, X86DEC_NEED_MORE, MN(INVALID), 0, 0},
  {"\xD8\x00", 2, 0, X86DEC_OK, MN(FADD), 2, "fadd dword ptr ds:[rax]"},
  {"\x66\x0F\x6F\xC0", 4, 0, X86DEC_OK, MN(MOVDQA), 4, "movdqa xmm0, xmm0"},
  {"\xC5\xF8\x77", 3, 0, X86DEC_OK, MN(VZEROUPPER), 3, "vzeroupper"},
  {"\x62\xF1\x7C\x48\x00", 5, 0, X86DEC_UNSUPPORTED, MN(INVALID), 0, 0},
  {"\x0F\x38\x00\x00", 4, 0, X86DEC_OK, MN(PSHUFB), 4,
      "pshufb mm0, qword ptr ds:[rax]"},
  {"\x0F\x0F\x00", 3, 0, X86DEC_NEED_MORE, MN(INVALID), 0, 0},
  {"\x8F\xC8", 2, 0, X86DEC_UNSUPPORTED, MN(INVALID), 0, 0},
  {"\x8F\xC8", 2, 1, X86DEC_INVALID, MN(INVALID), 0, 0},
  {"\xC4\xC0", 2, 1, X86DEC_INVALID, MN(INVALID), 0, 0},
  {"\x0F\x01\xC0", 3, 0, X86DEC_OK, MN(ENCLV), 3, "enclv"},
  {"\x0F\xC7\x38", 3, 0, X86DEC_OK, MN(VMPTRST), 3, "vmptrst qword ptr ds:[rax]"},
  {"\x0F\xAE\xC8", 3, 0, X86DEC_INVALID, MN(INVALID), 0, 0},
  {"\x66\x0F\xAE\xF8", 4, 0, X86DEC_UNSUPPORTED, MN(INVALID), 0, 0},
  {"\x0F\x20\x00", 3, 0, X86DEC_OK, MN(MOV), 3, "mov rax, cr0"},
  {"\x8C\xF6", 2, 0, X86DEC_INVALID, MN(INVALID), 0, 0},
  {"\xF3\x0F\xB8\xC1", 4, 0, X86DEC_OK, MN(POPCNT), 4, "popcnt eax, ecx"},
  {"\x0F\xB8\xC0", 3, 0, X86DEC_INVALID, MN(INVALID), 0, 0},
  {"\xF3\x0F\xAF\xC1", 4, 0, X86DEC_OK, MN(IMUL), 4, "imul eax, ecx"},
  {"\xF3\x0F\x1E\xFA", 4, 0, X86DEC_OK, MN(ENDBR64), 4, "endbr64"},
  {"\xF3\x0F\x1E\xFB", 4, 0, X86DEC_OK, MN(ENDBR32), 4, "endbr32"},
  {"\x66\x50", 2, 0, X86DEC_OK, MN(PUSH), 2, "push ax"},
};

static int check_one(const X86decDecoder* dec64, const X86decDecoder* dec32,
    const Vec* vector, size_t index)
{
  const X86decDecoder* dec = vector->legacy ? dec32 : dec64;
  X86decInsn insn = {0};
  X86decOperand ops[X86DEC_MAX_OPERANDS] = {0};
  enum x86dec_status_e st;
  char text[160];
  char bytes[48];
  size_t byte_count;
  size_t byte_pos = 0;

  for (byte_count = 0; byte_count < vector->len; byte_count++) {
    byte_pos += (size_t)snprintf(bytes + byte_pos, sizeof(bytes) - byte_pos,
        "%02X", (unsigned char)vector->code[byte_count]);
  }

  st = x86dec_decode_full(dec, vector->code, vector->len, &insn, ops,
      X86DEC_MAX_OPERANDS);

  if (st != vector->status) {
    printf("FAIL [%u] bytes=%s status %d, want %d\n", (unsigned)index, bytes,
        st, vector->status);
    return 1;
  }

  if (st != X86DEC_OK) {
    return 0;
  }

  if (insn.mnemonic != vector->mnemonic || insn.length != vector->insn_len) {
    printf("FAIL [%u] bytes=%s got %s/%u, want %s/%u\n", (unsigned)index,
        bytes, x86dec_mnemonic_text(insn.mnemonic), insn.length,
        x86dec_mnemonic_text(vector->mnemonic), vector->insn_len);
    return 1;
  }

  if (vector->text) {
    text[0] = 0;

    if (!x86dec_format_insn(&insn, ops, text, sizeof(text)) ||
        strcmp(text, vector->text)) {
      printf("FAIL [%u] bytes=%s got \"%s\", want \"%s\"\n", (unsigned)index,
          bytes, text, vector->text);
      return 1;
    }
  }

  return 0;
}

static const uint8_t bench_corpus[] = {
  0x48, 0x89, 0xE5, 0x48, 0x83, 0xEC, 0x28, 0x8B, 0x45, 0x08,
  0x0F, 0xAF, 0xC1, 0xE8, 0x00, 0x00, 0x00, 0x00, 0xC3, 0x90,
  0x0F, 0x1F, 0x44, 0x00, 0x00, 0x48, 0x8B, 0x4C, 0x24, 0x08
};
#define BENCH_REPS 200000

static void bench(const X86decDecoder* dec)
{
  X86decInsn insn;
  X86decOperand ops[4];
  LARGE_INTEGER freq;
  LARGE_INTEGER start;
  LARGE_INTEGER end;
  unsigned long long elapsed;
  unsigned long long micros;
  unsigned long long count = 0;
  int reps;

  QueryPerformanceFrequency(&freq);
  QueryPerformanceCounter(&start);

  for (reps = 0; reps < BENCH_REPS; reps++) {
    size_t offset = 0;

    while (offset < sizeof(bench_corpus)) {
      if (x86dec_decode_full(dec, bench_corpus + offset,
          sizeof(bench_corpus) - offset, &insn, ops, 4) != X86DEC_OK) {
        break;
      }

      offset += insn.length;
      count++;
    }
  }

  QueryPerformanceCounter(&end);

  elapsed = (unsigned long long)(end.QuadPart - start.QuadPart);
  micros = elapsed * 1000000ULL / (unsigned long long)freq.QuadPart;

  printf("decoded %llu insns in %llu us (%.2f M insns/s) [full, 1 thread]\n",
      count, micros, (double)count / (double)micros);
}

static void bench_insn_only(const X86decDecoder* dec)
{
  X86decInsn insn;
  LARGE_INTEGER freq;
  LARGE_INTEGER start;
  LARGE_INTEGER end;
  unsigned long long elapsed;
  unsigned long long micros;
  unsigned long long count = 0;
  int reps;

  QueryPerformanceFrequency(&freq);
  QueryPerformanceCounter(&start);

  for (reps = 0; reps < BENCH_REPS; reps++) {
    size_t offset = 0;

    while (offset < sizeof(bench_corpus)) {
      if (x86dec_decode_insn(dec, NULL, bench_corpus + offset,
          sizeof(bench_corpus) - offset, &insn) != X86DEC_OK) {
        break;
      }

      offset += insn.length;
      count++;
    }
  }

  QueryPerformanceCounter(&end);

  elapsed = (unsigned long long)(end.QuadPart - start.QuadPart);
  micros = elapsed * 1000000ULL / (unsigned long long)freq.QuadPart;

  printf("decoded %llu insns in %llu us (%.2f M insns/s) [insn-only, 1 thread]\n",
      count, micros, (double)count / (double)micros);
}

typedef struct {
  const X86decDecoder* dec;
  int reps;
  unsigned long long count;
} BenchThreadData;

static DWORD WINAPI bench_thread_proc(LPVOID param)
{
  BenchThreadData* data = (BenchThreadData*)param;
  X86decInsn insn;
  X86decOperand ops[4];
  int reps;
  size_t offset;
  unsigned long long count = 0;

  for (reps = 0; reps < data->reps; reps++) {
    offset = 0;

    while (offset < sizeof(bench_corpus)) {
      if (x86dec_decode_full(data->dec, bench_corpus + offset,
          sizeof(bench_corpus) - offset, &insn, ops, 4) != X86DEC_OK) {
        break;
      }

      offset += insn.length;
      count++;
    }
  }

  data->count = count;
  return 0;
}

static void bench_mt(const X86decDecoder* dec)
{
  SYSTEM_INFO sysinfo;
  DWORD thread_count;
  HANDLE handles[64];
  BenchThreadData thread_data[64];
  LARGE_INTEGER freq;
  LARGE_INTEGER start;
  LARGE_INTEGER end;
  unsigned long long elapsed;
  unsigned long long micros;
  unsigned long long total = 0;
  int base_reps;
  int remainder;
  DWORD i;

  GetSystemInfo(&sysinfo);
  thread_count = sysinfo.dwNumberOfProcessors;

  if (thread_count < 1) {
    thread_count = 1;
  }

  if (thread_count > 64) {
    thread_count = 64;
  }

  base_reps = BENCH_REPS / (int)thread_count;
  remainder = BENCH_REPS % (int)thread_count;

  QueryPerformanceFrequency(&freq);
  QueryPerformanceCounter(&start);

  for (i = 0; i < thread_count; i++) {
    thread_data[i].dec = dec;
    thread_data[i].reps = base_reps + ((int)i < remainder ? 1 : 0);
    thread_data[i].count = 0;
    handles[i] = CreateThread(NULL, 0, bench_thread_proc, &thread_data[i], 0,
        NULL);

    if (!handles[i]) {
      printf("thread create failed\n");
      return;
    }
  }

  WaitForMultipleObjects(thread_count, handles, TRUE, INFINITE);

  for (i = 0; i < thread_count; i++) {
    total += thread_data[i].count;
    CloseHandle(handles[i]);
  }

  QueryPerformanceCounter(&end);

  elapsed = (unsigned long long)(end.QuadPart - start.QuadPart);
  micros = elapsed * 1000000ULL / (unsigned long long)freq.QuadPart;

  printf("decoded %llu insns in %llu us (%.2f M insns/s) [full, %u threads]\n",
      total, micros, (double)total / (double)micros,
      (unsigned)thread_count);
}

int main(void)
{
  X86decDecoder dec64;
  X86decDecoder dec32;
  size_t total = sizeof(x86dec_vectors) / sizeof(x86dec_vectors[0]);
  size_t fails = 0;
  size_t i;

  if (!x86dec_decoder_init(&dec64, X86DEC_MODE_LONG_64, X86DEC_STACK_64)) {
    printf("decoder init failed\n");
    return 1;
  }

  if (!x86dec_decoder_init(&dec32, X86DEC_MODE_LEGACY_32, X86DEC_STACK_32)) {
    printf("decoder init failed\n");
    return 1;
  }

  for (i = 0; i < total; i++) {
    fails += (size_t)check_one(&dec64, &dec32, &x86dec_vectors[i], i);
  }

  for (i = 0; i < x86dec_vectors_ext_count; i++) {
    fails += (size_t)check_one(&dec64, &dec32, &x86dec_vectors_ext[i],
        total + i);
  }

  total += x86dec_vectors_ext_count;

  printf("%u/%u vectors passed\n", (unsigned)(total - fails),
      (unsigned)total);
  bench(&dec64);
  bench_insn_only(&dec64);
  bench_mt(&dec64);

  return fails ? 1 : 0;
}
