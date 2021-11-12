#ifndef CS_RISCVDISASSEMBLER_H
#define CS_RISCVDISASSEMBLER_H

#include "capstone/capstone.h"

#include "../../MCRegisterInfo.h"

void RISCV_init(MCRegisterInfo *MRI);

bool RISCV_getInstruction(csh handle, const uint8_t *code, size_t code_len,
		MCInst *instr, uint16_t *size, uint64_t address, void *info);

bool RISCV64_getInstruction(csh handle, const uint8_t *code, size_t code_len,
		MCInst *instr, uint16_t *size, uint64_t address, void *info);

#endif
