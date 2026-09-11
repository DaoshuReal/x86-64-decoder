#pragma once

#include <stdint.h>

#include "core/types.h"
#include "decode/decoder.h"
#include "scan.h"
#include "tables.h"

enum x86dec_status_e x86dec_decode_vex(const X86decDecoder* restrict decoder,
    X86decCursor* restrict cursor, X86decRaw* restrict raw,
    X86decEntry* restrict out, uint16_t* restrict fx);
