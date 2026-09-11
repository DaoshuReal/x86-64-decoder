#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "core/types.h"
#include "core/mnemonic.h"
#include "core/register.h"
#include "core/operand.h"

typedef struct {
  enum x86dec_machine_mode_e mode;
  enum x86dec_stack_width_e width;
} X86decDecoder;

typedef struct {
  uint8_t count;
  uint8_t bytes[8];
  bool lock;
  bool rep;
  bool repne;
  bool osz;
  bool asz;
  uint8_t segment;
  bool has_rex;
  uint8_t rex;
  bool has_modrm;
  uint8_t modrm;
  uint8_t modrm_offset;
  bool has_sib;
  uint8_t sib;
  uint8_t disp_size;
  int32_t disp;
  bool has_moffs;
  uint64_t moffs;
  uint8_t imm_size;
  uint64_t imm;
  uint8_t opcode_offset;
} X86decRaw;

typedef struct {
  enum x86dec_machine_mode_e mode;
  enum x86dec_mnemonic_e mnemonic;
  uint8_t length;
  uint8_t map;
  uint8_t opcode;
  uint8_t stack_width;
  uint8_t operand_width;
  uint8_t address_width;
  uint8_t operand_count;
  uint16_t flags;
  X86decRaw raw;
} X86decInsn;

enum x86dec_insn_flag_e {
  X86DEC_INSN_HAS_LOCK = 1u << 0,
  X86DEC_INSN_HAS_REP = 1u << 1,
  X86DEC_INSN_HAS_REPNE = 1u << 2,
  X86DEC_INSN_HAS_REX = 1u << 3,
  X86DEC_INSN_HAS_MODRM = 1u << 4,
  X86DEC_INSN_HAS_SIB = 1u << 5,
  X86DEC_INSN_OSZ_OVERRIDE = 1u << 6,
  X86DEC_INSN_ASZ_OVERRIDE = 1u << 7
};

typedef struct {
  uint8_t eosz;
  uint8_t easz;
  uint8_t has_rex;
  uint8_t rex;
  uint8_t modrm;
  uint8_t has_modrm;
  uint8_t sib;
  uint8_t has_sib;
  int32_t disp;
  uint8_t disp_size;
  uint64_t moffs;
  uint8_t has_moffs;
  uint64_t imm;
  uint8_t imm_size;
  uint16_t mnemonic;
  uint8_t count;
  uint8_t shapes[4];
  uint8_t fixed[4];
  uint8_t length;
  uint8_t opcode;
  uint8_t map;
  uint16_t flags;
  uint16_t mem_bits;
  uint8_t is_vex;
  uint8_t vex_l;
  uint8_t vex_w;
  uint8_t vex_vvvv;
  uint8_t vex_r;
  uint8_t vex_x;
  uint8_t vex_b;
  uint8_t vex_pp;
  uint8_t vex_map;
  uint8_t vex_opcode;
} X86decContext;

bool x86dec_decoder_init(X86decDecoder* decoder,
    enum x86dec_machine_mode_e mode, enum x86dec_stack_width_e width);

enum x86dec_status_e x86dec_decode_insn(const X86decDecoder* restrict decoder,
    X86decContext* restrict context, const void* restrict buffer, size_t length,
    X86decInsn* restrict insn);

enum x86dec_status_e x86dec_decode_operands(const X86decDecoder* restrict decoder,
    const X86decContext* restrict context, const X86decInsn* restrict insn,
    X86decOperand* restrict operands, uint8_t operand_count);

enum x86dec_status_e x86dec_decode_full(const X86decDecoder* restrict decoder,
    const void* restrict buffer, size_t length, X86decInsn* restrict insn,
    X86decOperand* restrict operands, uint8_t operand_count);
