#pragma once

#include <stddef.h>
#include <stdint.h>

#include "x86dec.h"

typedef struct {
  const char* code;
  uint8_t len;
  uint8_t legacy;
  enum x86dec_status_e status;
  enum x86dec_mnemonic_e mnemonic;
  uint8_t insn_len;
  const char* text;
} Vec;

extern const Vec x86dec_vectors_ext[];
extern const size_t x86dec_vectors_ext_count;
