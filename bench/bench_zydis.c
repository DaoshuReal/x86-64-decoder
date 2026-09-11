#include <stdio.h>

#include <Windows.h>

#include "x86dec.h"
#include "zydis.h"

#define REPS 200000

static const uint8_t corpus[] = {
  0x48, 0x89, 0xE5, 0x48, 0x83, 0xEC, 0x28, 0x8B, 0x45, 0x08,
  0x0F, 0xAF, 0xC1, 0xE8, 0x00, 0x00, 0x00, 0x00, 0xC3, 0x90,
  0x0F, 0x1F, 0x44, 0x00, 0x00, 0x48, 0x8B, 0x4C, 0x24, 0x08
};

static unsigned long long now_us(LARGE_INTEGER freq, LARGE_INTEGER start,
    LARGE_INTEGER end)
{
  unsigned long long elapsed = (unsigned long long)(end.QuadPart - start.QuadPart);
  return elapsed * 1000000ULL / (unsigned long long)freq.QuadPart;
}

int main(void)
{
  X86decDecoder dec;
  ZydisDecoder zdec;
  LARGE_INTEGER freq;
  LARGE_INTEGER start;
  LARGE_INTEGER end;
  unsigned long long micros;
  unsigned long long count;
  int reps;
  size_t offset;

  if (!x86dec_decoder_init(&dec, X86DEC_MODE_LONG_64, X86DEC_STACK_64)) {
    printf("x86dec init failed\n");
    return 1;
  }

  if (ZydisDecoderInit(&zdec, ZYDIS_MACHINE_MODE_LONG_64,
      ZYDIS_STACK_WIDTH_64) != ZYAN_STATUS_SUCCESS) {
    printf("zydis init failed\n");
    return 1;
  }

  printf("x86dec vs zydis decode benchmark (%d reps x 9 insns, same corpus/process)\n",
      REPS);

  /* warmup so icache and branch predictors settle before timing */
  for (reps = 0; reps < 2000; reps++) {
    X86decInsn insn;
    X86decOperand ops[4];
    ZydisDecodedInstruction zi;
    ZydisDecodedOperand zops[ZYDIS_MAX_OPERAND_COUNT];
    offset = 0;
    while (offset < sizeof(corpus)) {
      if (x86dec_decode_full(&dec, corpus + offset, sizeof(corpus) - offset,
          &insn, ops, 4) != X86DEC_OK || !insn.length) {
        break;
      }
      offset += insn.length;
    }
    offset = 0;
    while (offset < sizeof(corpus)) {
      if (ZydisDecoderDecodeFull(&zdec, corpus + offset, sizeof(corpus) - offset,
          &zi, zops) != ZYAN_STATUS_SUCCESS || !zi.length) {
        break;
      }
      offset += zi.length;
    }
  }

  /* x86dec full (insn + operands) */
  count = 0;
  QueryPerformanceFrequency(&freq);
  QueryPerformanceCounter(&start);
  for (reps = 0; reps < REPS; reps++) {
    X86decInsn insn;
    X86decOperand ops[4];
    offset = 0;
    while (offset < sizeof(corpus)) {
      if (x86dec_decode_full(&dec, corpus + offset, sizeof(corpus) - offset,
          &insn, ops, 4) != X86DEC_OK || !insn.length) {
        printf("x86dec full decode failed\n");
        return 1;
      }
      offset += insn.length;
      count++;
    }
  }
  QueryPerformanceCounter(&end);
  micros = now_us(freq, start, end);
  printf("decoded %llu insns in %llu us (%.2f M insns/s) [x86dec full, 1 thread]\n",
      count, micros, (double)count / (double)micros);
  if (count != (unsigned long long)REPS * 9) {
    printf("x86dec full count mismatch\n");
    return 1;
  }

  /* zydis full (insn + operands) */
  count = 0;
  QueryPerformanceFrequency(&freq);
  QueryPerformanceCounter(&start);
  for (reps = 0; reps < REPS; reps++) {
    ZydisDecodedInstruction zi;
    ZydisDecodedOperand zops[ZYDIS_MAX_OPERAND_COUNT];
    offset = 0;
    while (offset < sizeof(corpus)) {
      if (ZydisDecoderDecodeFull(&zdec, corpus + offset, sizeof(corpus) - offset,
          &zi, zops) != ZYAN_STATUS_SUCCESS || !zi.length) {
        printf("zydis full decode failed\n");
        return 1;
      }
      offset += zi.length;
      count++;
    }
  }
  QueryPerformanceCounter(&end);
  micros = now_us(freq, start, end);
  printf("decoded %llu insns in %llu us (%.2f M insns/s) [zydis full, 1 thread]\n",
      count, micros, (double)count / (double)micros);
  if (count != (unsigned long long)REPS * 9) {
    printf("zydis full count mismatch\n");
    return 1;
  }

  /* x86dec insn-only (no operands) */
  count = 0;
  QueryPerformanceFrequency(&freq);
  QueryPerformanceCounter(&start);
  for (reps = 0; reps < REPS; reps++) {
    X86decInsn insn;
    offset = 0;
    while (offset < sizeof(corpus)) {
      if (x86dec_decode_insn(&dec, NULL, corpus + offset,
          sizeof(corpus) - offset, &insn) != X86DEC_OK || !insn.length) {
        printf("x86dec insn decode failed\n");
        return 1;
      }
      offset += insn.length;
      count++;
    }
  }
  QueryPerformanceCounter(&end);
  micros = now_us(freq, start, end);
  printf("decoded %llu insns in %llu us (%.2f M insns/s) [x86dec insn-only, 1 thread]\n",
      count, micros, (double)count / (double)micros);
  if (count != (unsigned long long)REPS * 9) {
    printf("x86dec insn count mismatch\n");
    return 1;
  }

  /* zydis insn-only (no operands) */
  count = 0;
  QueryPerformanceFrequency(&freq);
  QueryPerformanceCounter(&start);
  for (reps = 0; reps < REPS; reps++) {
    ZydisDecodedInstruction zi;
    offset = 0;
    while (offset < sizeof(corpus)) {
      if (ZydisDecoderDecodeInstruction(&zdec, NULL, corpus + offset,
          sizeof(corpus) - offset, &zi) != ZYAN_STATUS_SUCCESS || !zi.length) {
        printf("zydis insn decode failed\n");
        return 1;
      }
      offset += zi.length;
      count++;
    }
  }
  QueryPerformanceCounter(&end);
  micros = now_us(freq, start, end);
  printf("decoded %llu insns in %llu us (%.2f M insns/s) [zydis insn-only, 1 thread]\n",
      count, micros, (double)count / (double)micros);
  if (count != (unsigned long long)REPS * 9) {
    printf("zydis insn count mismatch\n");
    return 1;
  }

  return 0;
}
