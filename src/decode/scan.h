#pragma once

#include <stddef.h>
#include <stdint.h>

#include "core/types.h"
#include "decode/decoder.h"

typedef struct {
  const uint8_t* p;
  size_t left;
  size_t pos;
} X86decCursor;

static inline int x86dec_take(X86decCursor* c, uint8_t* out)
{
  if (!c->left) {
    return 0;
  }
  *out = *c->p++;
  c->left--;
  c->pos++;
  return 1;
}

uint8_t x86dec_default_eosz(const X86decDecoder* decoder);
uint8_t x86dec_default_easz(const X86decDecoder* decoder);
enum x86dec_status_e x86dec_scan_prefixes(X86decCursor* c, X86decRaw* raw);
enum x86dec_status_e x86dec_scan_tail(X86decCursor* c, uint8_t easz,
    X86decRaw* raw);
