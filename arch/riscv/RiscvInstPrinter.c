//===-- RISCVInstPrinter.cpp - Convert RISCV MCInst to asm syntax ---------===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This class prints an RISCV MCInst to a .s file.
//
//===----------------------------------------------------------------------===//

#ifdef CAPSTONE_HAS_RISCV

#include <platform.h>
#include <stdlib.h>
#include <stdio.h>	// debug
#include <string.h>
#include <assert.h>

#include "../../MCInst.h"
#include "../../utils.h"
#include "../../SStream.h"
#include "../../MCRegisterInfo.h"
#include "RiscvMapping.h"

#include "RiscvInstPrinter.h"

#define GET_INSTRINFO_ENUM
#include "RiscvGenInstrInfo.inc"

static const char *getRegisterName(unsigned RegNo);
static void printInstruction(MCInst *MI, SStream *O, const MCRegisterInfo *MRI);
extern 

void RISCV_printInst(MCInst *MI, SStream *O, void *info)
{
	printInstruction(MI, O, NULL);
	// printAnnotation(O, Annot);
}

static void printRegName(SStream *O, unsigned RegNo)
{
	SStream_concat(O, "$%s", getRegisterName(RegNo));
}

static void printOperand(MCInst *MI, unsigned OpNo, SStream *O)
{
	MCOperand *Op;

	if (OpNo >= MI->size)
		return;

	Op = MCInst_getOperand(MI, OpNo);
	if (MCOperand_isReg(Op)) {
		unsigned int reg = MCOperand_getReg(Op);
		printRegName(O, reg);
		if (MI->csh->detail) {

			MI->flat_insn->detail->riscv.operands[MI->flat_insn->detail->riscv.op_count].type = RISCV_OP_REG;
			MI->flat_insn->detail->riscv.operands[MI->flat_insn->detail->riscv.op_count].reg = reg;
			MI->flat_insn->detail->riscv.op_count++;
		}
		return;
	} else if (MCOperand_isImm(Op)) {
		int64_t imm = MCOperand_getImm(Op);
		if (imm >= 0) {
			if (imm > HEX_THRESHOLD)
				SStream_concat(O, "0x%x", (unsigned int)imm);
			else
				SStream_concat(O, "%u", (unsigned int)imm);
		} else {
			if (imm < -HEX_THRESHOLD)
				// Cast first then negate
				SStream_concat(O, "-0x%x", -(uint32_t)imm);
			else
				SStream_concat(O, "-%u", (unsigned int)-imm);
		}
		if (MI->csh->detail) {
			MI->flat_insn->detail->riscv.operands[MI->flat_insn->detail->riscv.op_count].type = RISCV_OP_IMM;
			MI->flat_insn->detail->riscv.operands[MI->flat_insn->detail->riscv.op_count].imm = imm;
			MI->flat_insn->detail->riscv.op_count++;
		}
		return;
	}

	assert(0 && "Unknown operand kind in printOperand");
}

enum
{
	RISCVFenceField_I = 8,
	RISCVFenceField_O = 4,
	RISCVFenceField_R = 2,
	RISCVFenceField_W = 1,
};

void printFenceArg(MCInst *MI, unsigned OpNo, SStream *O)
{
	MCOperand *Op = MCInst_getOperand(MI, OpNo);

	int64_t FenceArg = MCOperand_getImm(Op);
	if ((FenceArg & RISCVFenceField_I) != 0)
		SStream_concat(O,"i");
	if ((FenceArg & RISCVFenceField_O) != 0)
		SStream_concat(O,"o");
	if ((FenceArg & RISCVFenceField_R) != 0)
		SStream_concat(O,"r");
	if ((FenceArg & RISCVFenceField_W) != 0)
		SStream_concat(O,"w");
}

#define PRINT_ALIAS_INSTR
#include "RiscvGenAsmWriter.inc"

#endif
