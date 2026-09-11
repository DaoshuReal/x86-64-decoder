#include "scan.h"

#include "core/register.h"

uint8_t x86dec_default_eosz(const X86decDecoder* decoder)
{
  if (decoder->width == X86DEC_STACK_16) {
    return 16;
  }

  return 32;
}

uint8_t x86dec_default_easz(const X86decDecoder* decoder)
{
  if (decoder->mode == X86DEC_MODE_LONG_64) {
    return 64;
  }

  return x86dec_default_eosz(decoder);
}

static const uint8_t x86dec_prefix_action[256] = {
  [0xF0] = 1, [0xF3] = 2, [0xF2] = 3,
  [0x2E] = 4, [0x36] = 5, [0x3E] = 6, [0x26] = 7,
  [0x64] = 8, [0x65] = 9, [0x66] = 10, [0x67] = 11,
};

enum x86dec_status_e x86dec_scan_prefixes(X86decCursor* restrict cursor,
    X86decRaw* restrict raw)
{
  for (;;) {
    uint8_t b;
    uint8_t a;

    if (X86DEC_UNLIKELY(!cursor->left || raw->count >= 8)) {
      return X86DEC_OK;
    }

    b = *cursor->p;
    a = x86dec_prefix_action[b];

    if (X86DEC_LIKELY(!a)) {
      return X86DEC_OK;
    }

    switch (a) {
      case 1:
        raw->lock = true;
        break;
      case 2:
        raw->rep = true;
        break;
      case 3:
        raw->repne = true;
        break;
      case 4:
        raw->segment = X86DEC_REG_CS;
        break;
      case 5:
        raw->segment = X86DEC_REG_SS;
        break;
      case 6:
        raw->segment = X86DEC_REG_DS;
        break;
      case 7:
        raw->segment = X86DEC_REG_ES;
        break;
      case 8:
        raw->segment = X86DEC_REG_FS;
        break;
      case 9:
        raw->segment = X86DEC_REG_GS;
        break;
      case 10:
        raw->osz = true;
        break;
      default:
        raw->asz = true;
        break;
    }

    raw->bytes[raw->count++] = b;

    cursor->p++;
    cursor->left--;
    cursor->pos++;
  }
}
