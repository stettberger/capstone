//===-- RISCVDisassembler.cpp - Disassembler for RISCV --------------------===//
//
//					   The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file implements the RISCVDisassembler class.
//
//===----------------------------------------------------------------------===//

#ifdef CAPSTONE_HAS_RISCV

#include <stdio.h>
#include <assert.h>
#include <string.h>

#include <platform.h>

#include "../../utils.h"

#include "../../MCInst.h"
#include "../../MCRegisterInfo.h"
#include "../../SStream.h"

#include "../../MathExtras.h"

// #include "MCTargetDesc/RISCVMCTargetDesc.h"
// #include "llvm/MC/MCContext.h"
#include "../../MCDisassembler.h"
#include "../../MCFixedLenDisassembler.h"
#include "../../MCInst.h"
#include "../../MCRegisterInfo.h"
// #include "llvm/MC/MCSubtargetInfo.h"
// #include "llvm/Support/Endian.h"
// #include "llvm/Support/TargetRegistry.h"

#define GET_SUBTARGETINFO_ENUM
#include "RiscvGenSubTargetInfo.inc"

static uint64_t getFeatureBits(int mode)
{
	uint64_t Bits = 0;

	// TODO: limited to the M extension (multiply) for now.
	Bits |= RISCV_FeatureStdExtM;

	if (mode & CS_MODE_32) {
		// nothing to do
	} else if (mode & CS_MODE_64) {
		Bits |= RISCV_Feature64Bit;
	}

	return Bits;
}

#define GET_REGINFO_ENUM
#include "RiscvGenRegisterInfo.inc"

static const unsigned GPRDecoderTable[] = {
	RISCV_X0,  RISCV_X1,  RISCV_X2,	 RISCV_X3,
	RISCV_X4,  RISCV_X5,  RISCV_X6,	 RISCV_X7,
	RISCV_X8,  RISCV_X9,  RISCV_X10, RISCV_X11,
	RISCV_X12, RISCV_X13, RISCV_X14, RISCV_X15,
	RISCV_X16, RISCV_X17, RISCV_X18, RISCV_X19,
	RISCV_X20, RISCV_X21, RISCV_X22, RISCV_X23,
	RISCV_X24, RISCV_X25, RISCV_X26, RISCV_X27,
	RISCV_X28, RISCV_X29, RISCV_X30, RISCV_X31
};

static DecodeStatus DecodeGPRRegisterClass(MCInst *Inst, uint64_t RegNo,
										   uint64_t Address,
										   const MCRegisterInfo *Decoder)
{
	if (RegNo > sizeof(GPRDecoderTable)) {
		return MCDisassembler_Fail;
	}

	// We must define our own mapping from RegNo to register identifier.
	// Accessing index RegNo in the register class will work in the case that
	// registers were added in ascending order, but not in general.
	unsigned Reg = GPRDecoderTable[RegNo];
	MCOperand_CreateReg0(Inst, Reg);
	return MCDisassembler_Success;
}

static const unsigned FPR32DecoderTable[] = {
	RISCV_F0_32,  RISCV_F1_32,	RISCV_F2_32,  RISCV_F3_32,
	RISCV_F4_32,  RISCV_F5_32,	RISCV_F6_32,  RISCV_F7_32,
	RISCV_F8_32,  RISCV_F9_32,	RISCV_F10_32, RISCV_F11_32,
	RISCV_F12_32, RISCV_F13_32, RISCV_F14_32, RISCV_F15_32,
	RISCV_F16_32, RISCV_F17_32, RISCV_F18_32, RISCV_F19_32,
	RISCV_F20_32, RISCV_F21_32, RISCV_F22_32, RISCV_F23_32,
	RISCV_F24_32, RISCV_F25_32, RISCV_F26_32, RISCV_F27_32,
	RISCV_F28_32, RISCV_F29_32, RISCV_F30_32, RISCV_F31_32
};

static DecodeStatus DecodeFPR32RegisterClass(MCInst *Inst, uint64_t RegNo,
											 uint64_t Address,
											 const MCRegisterInfo *Decoder) {
	if (RegNo > sizeof(FPR32DecoderTable)) {
		return MCDisassembler_Fail;
	}

	// We must define our own mapping from RegNo to register identifier.
	// Accessing index RegNo in the register class will work in the case that
	// registers were added in ascending order, but not in general.
	unsigned Reg = FPR32DecoderTable[RegNo];
	MCOperand_CreateReg0(Inst, Reg);
	return MCDisassembler_Success;
}

static const unsigned FPR64DecoderTable[] = {
	RISCV_F0_64,  RISCV_F1_64,	RISCV_F2_64,  RISCV_F3_64,
	RISCV_F4_64,  RISCV_F5_64,	RISCV_F6_64,  RISCV_F7_64,
	RISCV_F8_64,  RISCV_F9_64,	RISCV_F10_64, RISCV_F11_64,
	RISCV_F12_64, RISCV_F13_64, RISCV_F14_64, RISCV_F15_64,
	RISCV_F16_64, RISCV_F17_64, RISCV_F18_64, RISCV_F19_64,
	RISCV_F20_64, RISCV_F21_64, RISCV_F22_64, RISCV_F23_64,
	RISCV_F24_64, RISCV_F25_64, RISCV_F26_64, RISCV_F27_64,
	RISCV_F28_64, RISCV_F29_64, RISCV_F30_64, RISCV_F31_64
};

static DecodeStatus DecodeFPR64RegisterClass(MCInst *Inst, uint64_t RegNo,
											 uint64_t Address,
											 const MCRegisterInfo *Decoder) {
	if (RegNo > sizeof(FPR64DecoderTable)) {
		return MCDisassembler_Fail;
	}

	// We must define our own mapping from RegNo to register identifier.
	// Accessing index RegNo in the register class will work in the case that
	// registers were added in ascending order, but not in general.
	unsigned Reg = FPR64DecoderTable[RegNo];
	MCOperand_CreateReg0(Inst, Reg);
	return MCDisassembler_Success;
}

static DecodeStatus DecodeUImmOperand(MCInst *Inst, uint64_t Imm,
									  int64_t Address,
									  const MCRegisterInfo *Decoder) {
	MCOperand_CreateImm0(Inst, Imm);
	return MCDisassembler_Success;
}

static DecodeStatus DecodeSImmOperand_12(MCInst *Inst, uint64_t Imm,
										 int64_t Address,
										 const MCRegisterInfo *Decoder) {
	// Sign-extend the number in the bottom N = 12 bits of Imm
	MCOperand_CreateImm0(Inst, SignExtend32(Imm, 12)); // TODO: support 64 bits
	return MCDisassembler_Success;
}

static DecodeStatus DecodeSImmOperandAndLsl1_13(MCInst *Inst, uint64_t Imm,
												int64_t Address,
												const MCRegisterInfo *Decoder) {
	// Sign-extend the number in the bottom N bits of Imm after accounting for
	// the fact that the N=13 bit immediate is stored in N-1 bits (the LSB is
	// always zero)
	MCOperand_CreateImm0(Inst, SignExtend32((Imm << 1), 13)); // TODO: support 64 bits
	return MCDisassembler_Success;
}

static DecodeStatus DecodeSImmOperandAndLsl1_21(MCInst *Inst, uint64_t Imm,
												int64_t Address,
												const MCRegisterInfo *Decoder) {
	// Sign-extend the number in the bottom N bits of Imm after accounting for
	// the fact that the N=21 bit immediate is stored in N-1 bits (the LSB is
	// always zero)
	MCOperand_CreateImm0(Inst, SignExtend32((Imm << 1), 21)); // TODO: support 64 bits
	return MCDisassembler_Success;
}


#include "RiscvGenDisassemblerTables.inc"

static DecodeStatus readInstruction32(unsigned char *code, uint32_t *insn, bool isBigEndian)
{
	assert(!isBigEndian);

	*insn = (code[0] <<	 0) |
		(code[1] <<	 8) |
		(code[2] << 16) |
		(code[3] << 24);

	return MCDisassembler_Success;
}

static DecodeStatus RISCVDisassembler_getInstruction(
	int mode, MCInst *instr,
	const uint8_t *code, size_t code_len,
	uint16_t *Size,
	uint64_t Address, bool isBigEndian, MCRegisterInfo *MRI)
{
	uint32_t Insn;
	DecodeStatus Result;

	if (instr->flat_insn->detail) {
		memset(instr->flat_insn->detail, 0, sizeof(cs_detail));
	}

	// TODO: although assuming 4-byte instructions is sufficient for RV32 and
	// RV64, this will need modification when supporting the compressed
	// instruction set extension (RVC) which uses 16-bit instructions. Other
	// instruction set extensions have the option of defining instructions up to
	// 176 bits wide.
	if (code_len < 4) {
		return MCDisassembler_Fail;
	}

	Result = readInstruction32((unsigned char*)code, &Insn, isBigEndian);
	if (Result == MCDisassembler_Fail)
		return MCDisassembler_Fail;

	Result = decodeInstruction(DecoderTable32, instr, Insn, Address, MRI, mode);
	if (Result != MCDisassembler_Fail) {
		*Size = 4;
		return Result;
	}
	return MCDisassembler_Fail;
}

bool RISCV_getInstruction(csh ud, const uint8_t *code, size_t code_len, MCInst *instr,
						  uint16_t *size, uint64_t address, void *info)
{
	cs_struct *handle = (cs_struct *)(uintptr_t)ud;

	DecodeStatus status = RISCVDisassembler_getInstruction(handle->mode, instr,
														   code, code_len,
														   size,
														   address, MODE_IS_BIG_ENDIAN(handle->mode), (MCRegisterInfo *)info);

	return status == MCDisassembler_Success;
}

bool RISCV64_getInstruction(csh ud, const uint8_t *code, size_t code_len, MCInst *instr,
							uint16_t *size, uint64_t address, void *info)
{
	return false; // TODO: 64 bit mode
}

#define GET_REGINFO_MC_DESC
#include "RiscvGenRegisterInfo.inc"

void RISCV_init(MCRegisterInfo *MRI)
{
	MCRegisterInfo_InitMCRegisterInfo(MRI,
			RISCVRegDesc, sizeof(RISCVRegDesc) / sizeof(RISCVRegDesc[0]),
			0, 0,
			RISCVMCRegisterClasses, sizeof(RISCVMCRegisterClasses) / sizeof(RISCVMCRegisterClasses[0]),
			0, 0,
			RISCVRegDiffLists,
			0,
			RISCVSubRegIdxLists, sizeof(RISCVSubRegIdxLists) / sizeof(RISCVSubRegIdxLists[0]),
			0);
}

#endif
