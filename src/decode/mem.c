#include "scan.h"

enum x86dec_status_e x86dec_scan_tail(X86decCursor* restrict cursor, uint8_t easz,
    X86decRaw* restrict raw)
{
  uint8_t modrm;
  uint8_t mod;
  uint8_t rm;
  uint32_t disp = 0;
  uint8_t i;

  if (!x86dec_take(cursor, &modrm)) {
    return X86DEC_NEED_MORE;
  }

  raw->has_modrm = true;
  raw->modrm = modrm;
  raw->modrm_offset = (uint8_t)(cursor->pos - 1);

  mod = (uint8_t)(modrm >> 6);
  rm = (uint8_t)(modrm & 7);

  if (mod != 3) {
    if (easz == 16) {
      if (mod == 1) {
        raw->disp_size = 1;
      } else if (mod == 2 || rm == 6) {
        raw->disp_size = 2;
      }
    } else {
      uint8_t base = rm;

      if (rm == 4) {
        uint8_t sib;

        if (!x86dec_take(cursor, &sib)) {
          return X86DEC_NEED_MORE;
        }

        raw->has_sib = true;
        raw->sib = sib;
        base = (uint8_t)(sib & 7);
      }

      if (mod == 1) {
        raw->disp_size = 1;
      } else if (mod == 2 || base == 5) {
        raw->disp_size = 4;
      }
    }

    for (i = 0; i < raw->disp_size; i++) {
      uint8_t byte_value;

      if (!x86dec_take(cursor, &byte_value)) {
        return X86DEC_NEED_MORE;
      }

      disp |= (uint32_t)byte_value << (i * 8);
    }

    if (raw->disp_size == 1) {
      raw->disp = (int8_t)disp;
    } else if (raw->disp_size == 2) {
      raw->disp = (int16_t)disp;
    } else if (raw->disp_size == 4) {
      raw->disp = (int32_t)disp;
    }
  }

  return X86DEC_OK;
}
