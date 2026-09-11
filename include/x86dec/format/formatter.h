#pragma once

#include <stdbool.h>
#include <stddef.h>

#include "decode/decoder.h"

bool x86dec_format_insn(const X86decInsn* insn,
    const X86decOperand* operands, char* buffer, size_t size);

const char* x86dec_mnemonic_text(enum x86dec_mnemonic_e mnemonic);
const char* x86dec_register_text(enum x86dec_register_e reg);
