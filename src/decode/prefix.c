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

enum x86dec_status_e x86dec_scan_prefixes(X86decCursor* cursor, X86decRaw* raw)
{
  for (;;) {
    uint8_t b;

    if (!cursor->left || raw->count >= 8) {
      return X86DEC_OK;
    }

    b = *cursor->p;

    switch (b) {
      case 0xF0:
        raw->lock = true;
        break;
      case 0xF2:
        raw->repne = true;
        break;
      case 0xF3:
        raw->rep = true;
        break;
      case 0x2E:
        raw->segment = X86DEC_REG_CS;
        break;
      case 0x36:
        raw->segment = X86DEC_REG_SS;
        break;
      case 0x3E:
        raw->segment = X86DEC_REG_DS;
        break;
      case 0x26:
        raw->segment = X86DEC_REG_ES;
        break;
      case 0x64:
        raw->segment = X86DEC_REG_FS;
        break;
      case 0x65:
        raw->segment = X86DEC_REG_GS;
        break;
      case 0x66:
        raw->osz = true;
        break;
      case 0x67:
        raw->asz = true;
        break;
      default:
        return X86DEC_OK;
    }

    raw->bytes[raw->count++] = b;

    cursor->p++;
    cursor->left--;
    cursor->pos++;
  }
}
