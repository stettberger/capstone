#ifdef CAPSTONE_HAS_RISCV

#include <stdio.h>	// debug
#include <string.h>

#include "../../utils.h"

#include "RiscvMapping.h"

#define GET_INSTRINFO_ENUM
#include "RiscvGenInstrInfo.inc"

#ifndef CAPSTONE_DIET
static const name_map reg_name_maps[] = {
	{RISCV_REG_INVALID, NULL },
	{RISCV_REG_X0, "x0"},
	{RISCV_REG_X1, "x1"},
	{RISCV_REG_X2, "x2"},
	{RISCV_REG_X3, "x3"},
	{RISCV_REG_X4, "x4"},
	{RISCV_REG_X5, "x5"},
	{RISCV_REG_X6, "x6"},
	{RISCV_REG_X7, "x7"},
	{RISCV_REG_X8, "x8"},
	{RISCV_REG_X9, "x9"},
	{RISCV_REG_X10, "x10"},
	{RISCV_REG_X11, "x11"},
	{RISCV_REG_X12, "x12"},
	{RISCV_REG_X13, "x13"},
	{RISCV_REG_X14, "x14"},
	{RISCV_REG_X15, "x15"},
	{RISCV_REG_X16, "x16"},
	{RISCV_REG_X17, "x17"},
	{RISCV_REG_X18, "x18"},
	{RISCV_REG_X19, "x19"},
	{RISCV_REG_X20, "x20"},
	{RISCV_REG_X21, "x21"},
	{RISCV_REG_X22, "x22"},
	{RISCV_REG_X23, "x23"},
	{RISCV_REG_X24, "x24"},
	{RISCV_REG_X25, "x25"},
	{RISCV_REG_X26, "x26"},
	{RISCV_REG_X27, "x27"},
	{RISCV_REG_X28, "x28"},
	{RISCV_REG_X29, "x29"},
	{RISCV_REG_X30, "x30"},
	{RISCV_REG_X31, "x31"},
	{RISCV_REG_F0_32, "f0"},
	{RISCV_REG_F0_64, "f0"},
	{RISCV_REG_F1_32, "f1"},
	{RISCV_REG_F1_64, "f1"},
	{RISCV_REG_F2_32, "f2"},
	{RISCV_REG_F2_64, "f2"},
	{RISCV_REG_F3_32, "f3"},
	{RISCV_REG_F3_64, "f3"},
	{RISCV_REG_F4_32, "f4"},
	{RISCV_REG_F4_64, "f4"},
	{RISCV_REG_F5_32, "f5"},
	{RISCV_REG_F5_64, "f5"},
	{RISCV_REG_F6_32, "f6"},
	{RISCV_REG_F6_64, "f6"},
	{RISCV_REG_F7_32, "f7"},
	{RISCV_REG_F7_64, "f7"},
	{RISCV_REG_F8_32, "f8"},
	{RISCV_REG_F8_64, "f8"},
	{RISCV_REG_F9_32, "f9"},
	{RISCV_REG_F9_64, "f9"},
	{RISCV_REG_F10_32, "f10"},
	{RISCV_REG_F10_64, "f10"},
	{RISCV_REG_F11_32, "f11"},
	{RISCV_REG_F11_64, "f11"},
	{RISCV_REG_F12_32, "f12"},
	{RISCV_REG_F12_64, "f12"},
	{RISCV_REG_F13_32, "f13"},
	{RISCV_REG_F13_64, "f13"},
	{RISCV_REG_F14_32, "f14"},
	{RISCV_REG_F14_64, "f14"},
	{RISCV_REG_F15_32, "f15"},
	{RISCV_REG_F15_64, "f15"},
	{RISCV_REG_F16_32, "f16"},
	{RISCV_REG_F16_64, "f16"},
	{RISCV_REG_F17_32, "f17"},
	{RISCV_REG_F17_64, "f17"},
	{RISCV_REG_F18_32, "f18"},
	{RISCV_REG_F18_64, "f18"},
	{RISCV_REG_F19_32, "f19"},
	{RISCV_REG_F19_64, "f19"},
	{RISCV_REG_F20_32, "f20"},
	{RISCV_REG_F20_64, "f20"},
	{RISCV_REG_F21_32, "f21"},
	{RISCV_REG_F21_64, "f21"},
	{RISCV_REG_F22_32, "f22"},
	{RISCV_REG_F22_64, "f22"},
	{RISCV_REG_F23_32, "f23"},
	{RISCV_REG_F23_64, "f23"},
	{RISCV_REG_F24_32, "f24"},
	{RISCV_REG_F24_64, "f24"},
	{RISCV_REG_F25_32, "f25"},
	{RISCV_REG_F25_64, "f25"},
	{RISCV_REG_F26_32, "f26"},
	{RISCV_REG_F26_64, "f26"},
	{RISCV_REG_F27_32, "f27"},
	{RISCV_REG_F27_64, "f27"},
	{RISCV_REG_F28_32, "f28"},
	{RISCV_REG_F28_64, "f28"},
	{RISCV_REG_F29_32, "f29"},
	{RISCV_REG_F29_64, "f29"},
	{RISCV_REG_F30_32, "f30"},
	{RISCV_REG_F30_64, "f30"},
	{RISCV_REG_F31_32, "f31"},
	{RISCV_REG_F31_64, "f31"},
};
#endif

const char *RISCV_reg_name(csh handle, unsigned int reg)
{
#ifndef CAPSTONE_DIET
	if (reg >= RISCV_REG_ENDING)
		return NULL;

	return reg_name_maps[reg].name;
#else
	return NULL;
#endif
}

static const insn_map insns[] = {
	// dummy item
	{
		0, 0,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		RISCV_G_ADD, RISCV_INS_G_ADD,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_G_SUB, RISCV_INS_G_SUB,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_G_MUL, RISCV_INS_G_MUL,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_G_SDIV, RISCV_INS_G_SDIV,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_G_UDIV, RISCV_INS_G_UDIV,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_G_SREM, RISCV_INS_G_SREM,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_G_UREM, RISCV_INS_G_UREM,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_G_AND, RISCV_INS_G_AND,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_G_OR, RISCV_INS_G_OR,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_G_XOR, RISCV_INS_G_XOR,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_G_IMPLICIT_DEF, RISCV_INS_G_IMPLICIT_DEF,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_G_FRAME_INDEX, RISCV_INS_G_FRAME_INDEX,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_G_GLOBAL_VALUE, RISCV_INS_G_GLOBAL_VALUE,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_G_EXTRACT, RISCV_INS_G_EXTRACT,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_G_UNMERGE_VALUES, RISCV_INS_G_UNMERGE_VALUES,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_G_INSERT, RISCV_INS_G_INSERT,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_G_MERGE_VALUES, RISCV_INS_G_MERGE_VALUES,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_G_PTRTOINT, RISCV_INS_G_PTRTOINT,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_G_INTTOPTR, RISCV_INS_G_INTTOPTR,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_G_BITCAST, RISCV_INS_G_BITCAST,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_G_LOAD, RISCV_INS_G_LOAD,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_G_STORE, RISCV_INS_G_STORE,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_G_BRCOND, RISCV_INS_G_BRCOND,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_G_BRINDIRECT, RISCV_INS_G_BRINDIRECT,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_G_INTRINSIC, RISCV_INS_G_INTRINSIC,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_G_INTRINSIC_W_SIDE_EFFECTS, RISCV_INS_G_INTRINSIC_W_SIDE_EFFECTS,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_G_ANYEXT, RISCV_INS_G_ANYEXT,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_G_TRUNC, RISCV_INS_G_TRUNC,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_G_CONSTANT, RISCV_INS_G_CONSTANT,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_G_FCONSTANT, RISCV_INS_G_FCONSTANT,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_G_VASTART, RISCV_INS_G_VASTART,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_G_VAARG, RISCV_INS_G_VAARG,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_G_SEXT, RISCV_INS_G_SEXT,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_G_ZEXT, RISCV_INS_G_ZEXT,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_G_SHL, RISCV_INS_G_SHL,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_G_LSHR, RISCV_INS_G_LSHR,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_G_ASHR, RISCV_INS_G_ASHR,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_G_ICMP, RISCV_INS_G_ICMP,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_G_FCMP, RISCV_INS_G_FCMP,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_G_SELECT, RISCV_INS_G_SELECT,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_G_UADDE, RISCV_INS_G_UADDE,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_G_USUBE, RISCV_INS_G_USUBE,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_G_SADDO, RISCV_INS_G_SADDO,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_G_SSUBO, RISCV_INS_G_SSUBO,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_G_UMULO, RISCV_INS_G_UMULO,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_G_SMULO, RISCV_INS_G_SMULO,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_G_UMULH, RISCV_INS_G_UMULH,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_G_SMULH, RISCV_INS_G_SMULH,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_G_FADD, RISCV_INS_G_FADD,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_G_FSUB, RISCV_INS_G_FSUB,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_G_FMUL, RISCV_INS_G_FMUL,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_G_FMA, RISCV_INS_G_FMA,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_G_FDIV, RISCV_INS_G_FDIV,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_G_FREM, RISCV_INS_G_FREM,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_G_FPOW, RISCV_INS_G_FPOW,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_G_FEXP, RISCV_INS_G_FEXP,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_G_FEXP2, RISCV_INS_G_FEXP2,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_G_FLOG, RISCV_INS_G_FLOG,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_G_FLOG2, RISCV_INS_G_FLOG2,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_G_FNEG, RISCV_INS_G_FNEG,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_G_FPEXT, RISCV_INS_G_FPEXT,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_G_FPTRUNC, RISCV_INS_G_FPTRUNC,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_G_FPTOSI, RISCV_INS_G_FPTOSI,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_G_FPTOUI, RISCV_INS_G_FPTOUI,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_G_SITOFP, RISCV_INS_G_SITOFP,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_G_UITOFP, RISCV_INS_G_UITOFP,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_G_GEP, RISCV_INS_G_GEP,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_G_PTR_MASK, RISCV_INS_G_PTR_MASK,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_G_BR, RISCV_INS_G_BR,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_G_INSERT_VECTOR_ELT, RISCV_INS_G_INSERT_VECTOR_ELT,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_G_EXTRACT_VECTOR_ELT, RISCV_INS_G_EXTRACT_VECTOR_ELT,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_G_SHUFFLE_VECTOR, RISCV_INS_G_SHUFFLE_VECTOR,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_ADD, RISCV_INS_ADD,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_ADDI, RISCV_INS_ADDI,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_ADDIW, RISCV_INS_ADDIW,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_ADDW, RISCV_INS_ADDW,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_ADJCALLSTACKDOWN, RISCV_INS_ADJCALLSTACKDOWN,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_ADJCALLSTACKUP, RISCV_INS_ADJCALLSTACKUP,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_AMOADD_D, RISCV_INS_AMOADD_D,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_AMOADD_D_AQ, RISCV_INS_AMOADD_D_AQ,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_AMOADD_D_AQ_RL, RISCV_INS_AMOADD_D_AQ_RL,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_AMOADD_D_RL, RISCV_INS_AMOADD_D_RL,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_AMOADD_W, RISCV_INS_AMOADD_W,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_AMOADD_W_AQ, RISCV_INS_AMOADD_W_AQ,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_AMOADD_W_AQ_RL, RISCV_INS_AMOADD_W_AQ_RL,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_AMOADD_W_RL, RISCV_INS_AMOADD_W_RL,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_AMOAND_D, RISCV_INS_AMOAND_D,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_AMOAND_D_AQ, RISCV_INS_AMOAND_D_AQ,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_AMOAND_D_AQ_RL, RISCV_INS_AMOAND_D_AQ_RL,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_AMOAND_D_RL, RISCV_INS_AMOAND_D_RL,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_AMOAND_W, RISCV_INS_AMOAND_W,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_AMOAND_W_AQ, RISCV_INS_AMOAND_W_AQ,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_AMOAND_W_AQ_RL, RISCV_INS_AMOAND_W_AQ_RL,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_AMOAND_W_RL, RISCV_INS_AMOAND_W_RL,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_AMOMAXU_D, RISCV_INS_AMOMAXU_D,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_AMOMAXU_D_AQ, RISCV_INS_AMOMAXU_D_AQ,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_AMOMAXU_D_AQ_RL, RISCV_INS_AMOMAXU_D_AQ_RL,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_AMOMAXU_D_RL, RISCV_INS_AMOMAXU_D_RL,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_AMOMAXU_W, RISCV_INS_AMOMAXU_W,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_AMOMAXU_W_AQ, RISCV_INS_AMOMAXU_W_AQ,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_AMOMAXU_W_AQ_RL, RISCV_INS_AMOMAXU_W_AQ_RL,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_AMOMAXU_W_RL, RISCV_INS_AMOMAXU_W_RL,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_AMOMAX_D, RISCV_INS_AMOMAX_D,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_AMOMAX_D_AQ, RISCV_INS_AMOMAX_D_AQ,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_AMOMAX_D_AQ_RL, RISCV_INS_AMOMAX_D_AQ_RL,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_AMOMAX_D_RL, RISCV_INS_AMOMAX_D_RL,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_AMOMAX_W, RISCV_INS_AMOMAX_W,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_AMOMAX_W_AQ, RISCV_INS_AMOMAX_W_AQ,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_AMOMAX_W_AQ_RL, RISCV_INS_AMOMAX_W_AQ_RL,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_AMOMAX_W_RL, RISCV_INS_AMOMAX_W_RL,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_AMOMINU_D, RISCV_INS_AMOMINU_D,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_AMOMINU_D_AQ, RISCV_INS_AMOMINU_D_AQ,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_AMOMINU_D_AQ_RL, RISCV_INS_AMOMINU_D_AQ_RL,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_AMOMINU_D_RL, RISCV_INS_AMOMINU_D_RL,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_AMOMINU_W, RISCV_INS_AMOMINU_W,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_AMOMINU_W_AQ, RISCV_INS_AMOMINU_W_AQ,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_AMOMINU_W_AQ_RL, RISCV_INS_AMOMINU_W_AQ_RL,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_AMOMINU_W_RL, RISCV_INS_AMOMINU_W_RL,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_AMOMIN_D, RISCV_INS_AMOMIN_D,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_AMOMIN_D_AQ, RISCV_INS_AMOMIN_D_AQ,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_AMOMIN_D_AQ_RL, RISCV_INS_AMOMIN_D_AQ_RL,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_AMOMIN_D_RL, RISCV_INS_AMOMIN_D_RL,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_AMOMIN_W, RISCV_INS_AMOMIN_W,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_AMOMIN_W_AQ, RISCV_INS_AMOMIN_W_AQ,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_AMOMIN_W_AQ_RL, RISCV_INS_AMOMIN_W_AQ_RL,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_AMOMIN_W_RL, RISCV_INS_AMOMIN_W_RL,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_AMOOR_D, RISCV_INS_AMOOR_D,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_AMOOR_D_AQ, RISCV_INS_AMOOR_D_AQ,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_AMOOR_D_AQ_RL, RISCV_INS_AMOOR_D_AQ_RL,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_AMOOR_D_RL, RISCV_INS_AMOOR_D_RL,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_AMOOR_W, RISCV_INS_AMOOR_W,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_AMOOR_W_AQ, RISCV_INS_AMOOR_W_AQ,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_AMOOR_W_AQ_RL, RISCV_INS_AMOOR_W_AQ_RL,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_AMOOR_W_RL, RISCV_INS_AMOOR_W_RL,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_AMOSWAP_D, RISCV_INS_AMOSWAP_D,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_AMOSWAP_D_AQ, RISCV_INS_AMOSWAP_D_AQ,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_AMOSWAP_D_AQ_RL, RISCV_INS_AMOSWAP_D_AQ_RL,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_AMOSWAP_D_RL, RISCV_INS_AMOSWAP_D_RL,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_AMOSWAP_W, RISCV_INS_AMOSWAP_W,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_AMOSWAP_W_AQ, RISCV_INS_AMOSWAP_W_AQ,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_AMOSWAP_W_AQ_RL, RISCV_INS_AMOSWAP_W_AQ_RL,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_AMOSWAP_W_RL, RISCV_INS_AMOSWAP_W_RL,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_AMOXOR_D, RISCV_INS_AMOXOR_D,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_AMOXOR_D_AQ, RISCV_INS_AMOXOR_D_AQ,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_AMOXOR_D_AQ_RL, RISCV_INS_AMOXOR_D_AQ_RL,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_AMOXOR_D_RL, RISCV_INS_AMOXOR_D_RL,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_AMOXOR_W, RISCV_INS_AMOXOR_W,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_AMOXOR_W_AQ, RISCV_INS_AMOXOR_W_AQ,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_AMOXOR_W_AQ_RL, RISCV_INS_AMOXOR_W_AQ_RL,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_AMOXOR_W_RL, RISCV_INS_AMOXOR_W_RL,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_AND, RISCV_INS_AND,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_ANDI, RISCV_INS_ANDI,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_AUIPC, RISCV_INS_AUIPC,
#ifndef CAPSTONE_DIET
		{0}, {0}, {RISCV_GRP_LOAD_IMM}, 0, 0
#endif
	},
	{
		RISCV_BEQ, RISCV_INS_BEQ,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 1, 0
#endif
	},
	{
		RISCV_BGE, RISCV_INS_BGE,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 1, 0
#endif
	},
	{
		RISCV_BGEU, RISCV_INS_BGEU,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 1, 0
#endif
	},
	{
		RISCV_BLT, RISCV_INS_BLT,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 1, 0
#endif
	},
	{
		RISCV_BLTU, RISCV_INS_BLTU,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 1, 0
#endif
	},
	{
		RISCV_BNE, RISCV_INS_BNE,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 1, 0
#endif
	},
	{
		RISCV_CSRRC, RISCV_INS_CSRRC,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_CSRRCI, RISCV_INS_CSRRCI,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_CSRRS, RISCV_INS_CSRRS,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_CSRRSI, RISCV_INS_CSRRSI,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_CSRRW, RISCV_INS_CSRRW,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_CSRRWI, RISCV_INS_CSRRWI,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_DIV, RISCV_INS_DIV,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_DIVU, RISCV_INS_DIVU,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_DIVUW, RISCV_INS_DIVUW,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_DIVW, RISCV_INS_DIVW,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_EBREAK, RISCV_INS_EBREAK,
#ifndef CAPSTONE_DIET
		{0}, {0}, {RISCV_GRP_INT}, 0, 0
#endif
	},
	{
		RISCV_ECALL, RISCV_INS_ECALL,
#ifndef CAPSTONE_DIET
		{0}, {0}, {RISCV_GRP_INT}, 0, 0
#endif
	},
	{
		RISCV_FADD_D, RISCV_INS_FADD_D,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_FADD_S, RISCV_INS_FADD_S,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_FCLASS_D, RISCV_INS_FCLASS_D,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_FCLASS_S, RISCV_INS_FCLASS_S,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_FCVT_D_L, RISCV_INS_FCVT_D_L,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_FCVT_D_LU, RISCV_INS_FCVT_D_LU,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_FCVT_D_S, RISCV_INS_FCVT_D_S,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_FCVT_D_W, RISCV_INS_FCVT_D_W,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_FCVT_D_WU, RISCV_INS_FCVT_D_WU,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_FCVT_LU_D, RISCV_INS_FCVT_LU_D,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_FCVT_LU_S, RISCV_INS_FCVT_LU_S,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_FCVT_L_D, RISCV_INS_FCVT_L_D,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_FCVT_L_S, RISCV_INS_FCVT_L_S,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_FCVT_S_D, RISCV_INS_FCVT_S_D,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_FCVT_S_L, RISCV_INS_FCVT_S_L,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_FCVT_S_LU, RISCV_INS_FCVT_S_LU,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_FCVT_S_W, RISCV_INS_FCVT_S_W,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_FCVT_S_WU, RISCV_INS_FCVT_S_WU,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_FCVT_WU_D, RISCV_INS_FCVT_WU_D,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_FCVT_WU_S, RISCV_INS_FCVT_WU_S,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_FCVT_W_D, RISCV_INS_FCVT_W_D,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_FCVT_W_S, RISCV_INS_FCVT_W_S,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_FDIV_D, RISCV_INS_FDIV_D,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_FDIV_S, RISCV_INS_FDIV_S,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_FENCE, RISCV_INS_FENCE,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_FENCE_I, RISCV_INS_FENCE_I,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_FEQ_D, RISCV_INS_FEQ_D,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_FEQ_S, RISCV_INS_FEQ_S,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_FLD, RISCV_INS_FLD,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_FLE_D, RISCV_INS_FLE_D,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_FLE_S, RISCV_INS_FLE_S,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_FLT_D, RISCV_INS_FLT_D,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_FLT_S, RISCV_INS_FLT_S,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_FLW, RISCV_INS_FLW,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_FMADD_D, RISCV_INS_FMADD_D,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_FMADD_S, RISCV_INS_FMADD_S,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_FMAX_D, RISCV_INS_FMAX_D,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_FMAX_S, RISCV_INS_FMAX_S,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_FMIN_D, RISCV_INS_FMIN_D,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_FMIN_S, RISCV_INS_FMIN_S,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_FMSUB_D, RISCV_INS_FMSUB_D,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_FMSUB_S, RISCV_INS_FMSUB_S,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_FMUL_D, RISCV_INS_FMUL_D,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_FMUL_S, RISCV_INS_FMUL_S,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_FMV_D_X, RISCV_INS_FMV_D_X,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_FMV_W_X, RISCV_INS_FMV_W_X,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_FMV_X_D, RISCV_INS_FMV_X_D,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_FMV_X_W, RISCV_INS_FMV_X_W,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_FNMADD_D, RISCV_INS_FNMADD_D,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_FNMADD_S, RISCV_INS_FNMADD_S,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_FNMSUB_D, RISCV_INS_FNMSUB_D,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_FNMSUB_S, RISCV_INS_FNMSUB_S,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_FSD, RISCV_INS_FSD,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_FSGNJN_D, RISCV_INS_FSGNJN_D,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_FSGNJN_S, RISCV_INS_FSGNJN_S,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_FSGNJX_D, RISCV_INS_FSGNJX_D,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_FSGNJX_S, RISCV_INS_FSGNJX_S,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_FSGNJ_D, RISCV_INS_FSGNJ_D,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_FSGNJ_S, RISCV_INS_FSGNJ_S,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_FSQRT_D, RISCV_INS_FSQRT_D,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_FSQRT_S, RISCV_INS_FSQRT_S,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_FSUB_D, RISCV_INS_FSUB_D,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_FSUB_S, RISCV_INS_FSUB_S,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_FSW, RISCV_INS_FSW,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_JAL, RISCV_INS_JAL,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 1, 0
#endif
	},
	{
		RISCV_JALR, RISCV_INS_JALR,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 1
#endif
	},
	{
		RISCV_LB, RISCV_INS_LB,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_LBU, RISCV_INS_LBU,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_LD, RISCV_INS_LD,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_LEA_FI, RISCV_INS_LEA_FI,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_LH, RISCV_INS_LH,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_LHU, RISCV_INS_LHU,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_LR_D, RISCV_INS_LR_D,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_LR_D_AQ, RISCV_INS_LR_D_AQ,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_LR_D_AQ_RL, RISCV_INS_LR_D_AQ_RL,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_LR_D_RL, RISCV_INS_LR_D_RL,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_LR_W, RISCV_INS_LR_W,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_LR_W_AQ, RISCV_INS_LR_W_AQ,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_LR_W_AQ_RL, RISCV_INS_LR_W_AQ_RL,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_LR_W_RL, RISCV_INS_LR_W_RL,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_LUI, RISCV_INS_LUI,
#ifndef CAPSTONE_DIET
		{0}, {0}, {RISCV_GRP_LOAD_IMM}, 0, 0
#endif
	},
	{
		RISCV_LW, RISCV_INS_LW,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_LWU, RISCV_INS_LWU,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_LW_FI, RISCV_INS_LW_FI,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_MUL, RISCV_INS_MUL,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_MULH, RISCV_INS_MULH,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_MULHSU, RISCV_INS_MULHSU,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_MULHU, RISCV_INS_MULHU,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_MULW, RISCV_INS_MULW,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_OR, RISCV_INS_OR,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_ORI, RISCV_INS_ORI,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_PseudoBR, RISCV_INS_PseudoBR,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_PseudoBRIND, RISCV_INS_PseudoBRIND,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_PseudoCALL, RISCV_INS_PseudoCALL,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_PseudoRET, RISCV_INS_PseudoRET,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_REM, RISCV_INS_REM,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_REMU, RISCV_INS_REMU,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_REMUW, RISCV_INS_REMUW,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_REMW, RISCV_INS_REMW,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_SB, RISCV_INS_SB,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_SC_D, RISCV_INS_SC_D,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_SC_D_AQ, RISCV_INS_SC_D_AQ,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_SC_D_AQ_RL, RISCV_INS_SC_D_AQ_RL,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_SC_D_RL, RISCV_INS_SC_D_RL,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_SC_W, RISCV_INS_SC_W,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_SC_W_AQ, RISCV_INS_SC_W_AQ,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_SC_W_AQ_RL, RISCV_INS_SC_W_AQ_RL,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_SC_W_RL, RISCV_INS_SC_W_RL,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_SD, RISCV_INS_SD,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_SH, RISCV_INS_SH,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_SLL, RISCV_INS_SLL,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_SLLI, RISCV_INS_SLLI,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_SLLIW, RISCV_INS_SLLIW,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_SLLW, RISCV_INS_SLLW,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_SLT, RISCV_INS_SLT,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_SLTI, RISCV_INS_SLTI,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_SLTIU, RISCV_INS_SLTIU,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_SLTU, RISCV_INS_SLTU,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_SRA, RISCV_INS_SRA,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_SRAI, RISCV_INS_SRAI,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_SRAIW, RISCV_INS_SRAIW,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_SRAW, RISCV_INS_SRAW,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_SRL, RISCV_INS_SRL,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_SRLI, RISCV_INS_SRLI,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_SRLIW, RISCV_INS_SRLIW,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_SRLW, RISCV_INS_SRLW,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_SUB, RISCV_INS_SUB,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_SUBW, RISCV_INS_SUBW,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_SW, RISCV_INS_SW,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_SW_FI, RISCV_INS_SW_FI,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_Select, RISCV_INS_Select,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_XOR, RISCV_INS_XOR,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	},
	{
		RISCV_XORI, RISCV_INS_XORI,
#ifndef CAPSTONE_DIET
		{0}, {0}, {0}, 0, 0
#endif
	}
};

// given internal insn id, return public instruction info
void RISCV_get_insn_id(cs_struct *h, cs_insn *insn, unsigned int id)
{
	unsigned int i;

	i = insn_find(insns, ARR_SIZE(insns), id, &h->insn_cache);
	if (i != 0) {
		insn->id = insns[i].mapid;

		if (h->detail) {
#ifndef CAPSTONE_DIET
			memcpy(insn->detail->regs_read, insns[i].regs_use, sizeof(insns[i].regs_use));
			insn->detail->regs_read_count = (uint8_t)count_positive(insns[i].regs_use);

			memcpy(insn->detail->regs_write, insns[i].regs_mod, sizeof(insns[i].regs_mod));
			insn->detail->regs_write_count = (uint8_t)count_positive(insns[i].regs_mod);

			memcpy(insn->detail->groups, insns[i].groups, sizeof(insns[i].groups));
			insn->detail->groups_count = (uint8_t)count_positive(insns[i].groups);

			if (insns[i].branch || insns[i].indirect_branch) {
				// this insn also belongs to JUMP group. add JUMP group
				insn->detail->groups[insn->detail->groups_count] = MIPS_GRP_JUMP;
				insn->detail->groups_count++;
			}
#endif
		}
	}
}

// TODO: Do all of these belong here and the other places?
// Consider e.g. RISCV_INS_G_INTRINSIC_W_SIDE_EFFECTS
// How is ADD different from G_ADD?
static const name_map insn_name_maps[] = {
	{ RISCV_INS_G_ADD, "g_add" },
	{ RISCV_INS_G_SUB, "g_sub" },
	{ RISCV_INS_G_MUL, "g_mul" },
	{ RISCV_INS_G_SDIV, "g_sdiv" },
	{ RISCV_INS_G_UDIV, "g_udiv" },
	{ RISCV_INS_G_SREM, "g_srem" },
	{ RISCV_INS_G_UREM, "g_urem" },
	{ RISCV_INS_G_AND, "g_and" },
	{ RISCV_INS_G_OR, "g_or" },
	{ RISCV_INS_G_XOR, "g_xor" },
	{ RISCV_INS_G_IMPLICIT_DEF, "g_implicit_def" },
	{ RISCV_INS_G_FRAME_INDEX, "g_frame_index" },
	{ RISCV_INS_G_GLOBAL_VALUE, "g_global_value" },
	{ RISCV_INS_G_EXTRACT, "g_extract" },
	{ RISCV_INS_G_UNMERGE_VALUES, "g_unmerge_values" },
	{ RISCV_INS_G_INSERT, "g_insert" },
	{ RISCV_INS_G_MERGE_VALUES, "g_merge_values" },
	{ RISCV_INS_G_PTRTOINT, "g_ptrtoint" },
	{ RISCV_INS_G_INTTOPTR, "g_inttoptr" },
	{ RISCV_INS_G_BITCAST, "g_bitcast" },
	{ RISCV_INS_G_LOAD, "g_load" },
	{ RISCV_INS_G_STORE, "g_store" },
	{ RISCV_INS_G_BRCOND, "g_brcond" },
	{ RISCV_INS_G_BRINDIRECT, "g_brindirect" },
	{ RISCV_INS_G_INTRINSIC, "g_intrinsic" },
	{ RISCV_INS_G_INTRINSIC_W_SIDE_EFFECTS, "g_intrinsic_w_side_effects" },
	{ RISCV_INS_G_ANYEXT, "g_anyext" },
	{ RISCV_INS_G_TRUNC, "g_trunc" },
	{ RISCV_INS_G_CONSTANT, "g_constant" },
	{ RISCV_INS_G_FCONSTANT, "g_fconstant" },
	{ RISCV_INS_G_VASTART, "g_vastart" },
	{ RISCV_INS_G_VAARG, "g_vaarg" },
	{ RISCV_INS_G_SEXT, "g_sext" },
	{ RISCV_INS_G_ZEXT, "g_zext" },
	{ RISCV_INS_G_SHL, "g_shl" },
	{ RISCV_INS_G_LSHR, "g_lshr" },
	{ RISCV_INS_G_ASHR, "g_ashr" },
	{ RISCV_INS_G_ICMP, "g_icmp" },
	{ RISCV_INS_G_FCMP, "g_fcmp" },
	{ RISCV_INS_G_SELECT, "g_select" },
	{ RISCV_INS_G_UADDE, "g_uadde" },
	{ RISCV_INS_G_USUBE, "g_usube" },
	{ RISCV_INS_G_SADDO, "g_saddo" },
	{ RISCV_INS_G_SSUBO, "g_ssubo" },
	{ RISCV_INS_G_UMULO, "g_umulo" },
	{ RISCV_INS_G_SMULO, "g_smulo" },
	{ RISCV_INS_G_UMULH, "g_umulh" },
	{ RISCV_INS_G_SMULH, "g_smulh" },
	{ RISCV_INS_G_FADD, "g_fadd" },
	{ RISCV_INS_G_FSUB, "g_fsub" },
	{ RISCV_INS_G_FMUL, "g_fmul" },
	{ RISCV_INS_G_FMA, "g_fma" },
	{ RISCV_INS_G_FDIV, "g_fdiv" },
	{ RISCV_INS_G_FREM, "g_frem" },
	{ RISCV_INS_G_FPOW, "g_fpow" },
	{ RISCV_INS_G_FEXP, "g_fexp" },
	{ RISCV_INS_G_FEXP2, "g_fexp2" },
	{ RISCV_INS_G_FLOG, "g_flog" },
	{ RISCV_INS_G_FLOG2, "g_flog2" },
	{ RISCV_INS_G_FNEG, "g_fneg" },
	{ RISCV_INS_G_FPEXT, "g_fpext" },
	{ RISCV_INS_G_FPTRUNC, "g_fptrunc" },
	{ RISCV_INS_G_FPTOSI, "g_fptosi" },
	{ RISCV_INS_G_FPTOUI, "g_fptoui" },
	{ RISCV_INS_G_SITOFP, "g_sitofp" },
	{ RISCV_INS_G_UITOFP, "g_uitofp" },
	{ RISCV_INS_G_GEP, "g_gep" },
	{ RISCV_INS_G_PTR_MASK, "g_ptr_mask" },
	{ RISCV_INS_G_BR, "g_br" },
	{ RISCV_INS_G_INSERT_VECTOR_ELT, "g_insert_vector_elt" },
	{ RISCV_INS_G_EXTRACT_VECTOR_ELT, "g_extract_vector_elt" },
	{ RISCV_INS_G_SHUFFLE_VECTOR, "g_shuffle_vector" },
	{ RISCV_INS_ADD, "add" },
	{ RISCV_INS_ADDI, "addi" },
	{ RISCV_INS_ADDIW, "addiw" },
	{ RISCV_INS_ADDW, "addw" },
	{ RISCV_INS_ADJCALLSTACKDOWN, "adjcallstackdown" },
	{ RISCV_INS_ADJCALLSTACKUP, "adjcallstackup" },
	{ RISCV_INS_AMOADD_D, "amoadd_d" },
	{ RISCV_INS_AMOADD_D_AQ, "amoadd_d_aq" },
	{ RISCV_INS_AMOADD_D_AQ_RL, "amoadd_d_aq_rl" },
	{ RISCV_INS_AMOADD_D_RL, "amoadd_d_rl" },
	{ RISCV_INS_AMOADD_W, "amoadd_w" },
	{ RISCV_INS_AMOADD_W_AQ, "amoadd_w_aq" },
	{ RISCV_INS_AMOADD_W_AQ_RL, "amoadd_w_aq_rl" },
	{ RISCV_INS_AMOADD_W_RL, "amoadd_w_rl" },
	{ RISCV_INS_AMOAND_D, "amoand_d" },
	{ RISCV_INS_AMOAND_D_AQ, "amoand_d_aq" },
	{ RISCV_INS_AMOAND_D_AQ_RL, "amoand_d_aq_rl" },
	{ RISCV_INS_AMOAND_D_RL, "amoand_d_rl" },
	{ RISCV_INS_AMOAND_W, "amoand_w" },
	{ RISCV_INS_AMOAND_W_AQ, "amoand_w_aq" },
	{ RISCV_INS_AMOAND_W_AQ_RL, "amoand_w_aq_rl" },
	{ RISCV_INS_AMOAND_W_RL, "amoand_w_rl" },
	{ RISCV_INS_AMOMAXU_D, "amomaxu_d" },
	{ RISCV_INS_AMOMAXU_D_AQ, "amomaxu_d_aq" },
	{ RISCV_INS_AMOMAXU_D_AQ_RL, "amomaxu_d_aq_rl" },
	{ RISCV_INS_AMOMAXU_D_RL, "amomaxu_d_rl" },
	{ RISCV_INS_AMOMAXU_W, "amomaxu_w" },
	{ RISCV_INS_AMOMAXU_W_AQ, "amomaxu_w_aq" },
	{ RISCV_INS_AMOMAXU_W_AQ_RL, "amomaxu_w_aq_rl" },
	{ RISCV_INS_AMOMAXU_W_RL, "amomaxu_w_rl" },
	{ RISCV_INS_AMOMAX_D, "amomax_d" },
	{ RISCV_INS_AMOMAX_D_AQ, "amomax_d_aq" },
	{ RISCV_INS_AMOMAX_D_AQ_RL, "amomax_d_aq_rl" },
	{ RISCV_INS_AMOMAX_D_RL, "amomax_d_rl" },
	{ RISCV_INS_AMOMAX_W, "amomax_w" },
	{ RISCV_INS_AMOMAX_W_AQ, "amomax_w_aq" },
	{ RISCV_INS_AMOMAX_W_AQ_RL, "amomax_w_aq_rl" },
	{ RISCV_INS_AMOMAX_W_RL, "amomax_w_rl" },
	{ RISCV_INS_AMOMINU_D, "amominu_d" },
	{ RISCV_INS_AMOMINU_D_AQ, "amominu_d_aq" },
	{ RISCV_INS_AMOMINU_D_AQ_RL, "amominu_d_aq_rl" },
	{ RISCV_INS_AMOMINU_D_RL, "amominu_d_rl" },
	{ RISCV_INS_AMOMINU_W, "amominu_w" },
	{ RISCV_INS_AMOMINU_W_AQ, "amominu_w_aq" },
	{ RISCV_INS_AMOMINU_W_AQ_RL, "amominu_w_aq_rl" },
	{ RISCV_INS_AMOMINU_W_RL, "amominu_w_rl" },
	{ RISCV_INS_AMOMIN_D, "amomin_d" },
	{ RISCV_INS_AMOMIN_D_AQ, "amomin_d_aq" },
	{ RISCV_INS_AMOMIN_D_AQ_RL, "amomin_d_aq_rl" },
	{ RISCV_INS_AMOMIN_D_RL, "amomin_d_rl" },
	{ RISCV_INS_AMOMIN_W, "amomin_w" },
	{ RISCV_INS_AMOMIN_W_AQ, "amomin_w_aq" },
	{ RISCV_INS_AMOMIN_W_AQ_RL, "amomin_w_aq_rl" },
	{ RISCV_INS_AMOMIN_W_RL, "amomin_w_rl" },
	{ RISCV_INS_AMOOR_D, "amoor_d" },
	{ RISCV_INS_AMOOR_D_AQ, "amoor_d_aq" },
	{ RISCV_INS_AMOOR_D_AQ_RL, "amoor_d_aq_rl" },
	{ RISCV_INS_AMOOR_D_RL, "amoor_d_rl" },
	{ RISCV_INS_AMOOR_W, "amoor_w" },
	{ RISCV_INS_AMOOR_W_AQ, "amoor_w_aq" },
	{ RISCV_INS_AMOOR_W_AQ_RL, "amoor_w_aq_rl" },
	{ RISCV_INS_AMOOR_W_RL, "amoor_w_rl" },
	{ RISCV_INS_AMOSWAP_D, "amoswap_d" },
	{ RISCV_INS_AMOSWAP_D_AQ, "amoswap_d_aq" },
	{ RISCV_INS_AMOSWAP_D_AQ_RL, "amoswap_d_aq_rl" },
	{ RISCV_INS_AMOSWAP_D_RL, "amoswap_d_rl" },
	{ RISCV_INS_AMOSWAP_W, "amoswap_w" },
	{ RISCV_INS_AMOSWAP_W_AQ, "amoswap_w_aq" },
	{ RISCV_INS_AMOSWAP_W_AQ_RL, "amoswap_w_aq_rl" },
	{ RISCV_INS_AMOSWAP_W_RL, "amoswap_w_rl" },
	{ RISCV_INS_AMOXOR_D, "amoxor_d" },
	{ RISCV_INS_AMOXOR_D_AQ, "amoxor_d_aq" },
	{ RISCV_INS_AMOXOR_D_AQ_RL, "amoxor_d_aq_rl" },
	{ RISCV_INS_AMOXOR_D_RL, "amoxor_d_rl" },
	{ RISCV_INS_AMOXOR_W, "amoxor_w" },
	{ RISCV_INS_AMOXOR_W_AQ, "amoxor_w_aq" },
	{ RISCV_INS_AMOXOR_W_AQ_RL, "amoxor_w_aq_rl" },
	{ RISCV_INS_AMOXOR_W_RL, "amoxor_w_rl" },
	{ RISCV_INS_AND, "and" },
	{ RISCV_INS_ANDI, "andi" },
	{ RISCV_INS_AUIPC, "auipc" },
	{ RISCV_INS_BEQ, "beq" },
	{ RISCV_INS_BGE, "bge" },
	{ RISCV_INS_BGEU, "bgeu" },
	{ RISCV_INS_BLT, "blt" },
	{ RISCV_INS_BLTU, "bltu" },
	{ RISCV_INS_BNE, "bne" },
	{ RISCV_INS_CSRRC, "csrrc" },
	{ RISCV_INS_CSRRCI, "csrrci" },
	{ RISCV_INS_CSRRS, "csrrs" },
	{ RISCV_INS_CSRRSI, "csrrsi" },
	{ RISCV_INS_CSRRW, "csrrw" },
	{ RISCV_INS_CSRRWI, "csrrwi" },
	{ RISCV_INS_DIV, "div" },
	{ RISCV_INS_DIVU, "divu" },
	{ RISCV_INS_DIVUW, "divuw" },
	{ RISCV_INS_DIVW, "divw" },
	{ RISCV_INS_EBREAK, "ebreak" },
	{ RISCV_INS_ECALL, "ecall" },
	{ RISCV_INS_FADD_D, "fadd_d" },
	{ RISCV_INS_FADD_S, "fadd_s" },
	{ RISCV_INS_FCLASS_D, "fclass_d" },
	{ RISCV_INS_FCLASS_S, "fclass_s" },
	{ RISCV_INS_FCVT_D_L, "fcvt_d_l" },
	{ RISCV_INS_FCVT_D_LU, "fcvt_d_lu" },
	{ RISCV_INS_FCVT_D_S, "fcvt_d_s" },
	{ RISCV_INS_FCVT_D_W, "fcvt_d_w" },
	{ RISCV_INS_FCVT_D_WU, "fcvt_d_wu" },
	{ RISCV_INS_FCVT_LU_D, "fcvt_lu_d" },
	{ RISCV_INS_FCVT_LU_S, "fcvt_lu_s" },
	{ RISCV_INS_FCVT_L_D, "fcvt_l_d" },
	{ RISCV_INS_FCVT_L_S, "fcvt_l_s" },
	{ RISCV_INS_FCVT_S_D, "fcvt_s_d" },
	{ RISCV_INS_FCVT_S_L, "fcvt_s_l" },
	{ RISCV_INS_FCVT_S_LU, "fcvt_s_lu" },
	{ RISCV_INS_FCVT_S_W, "fcvt_s_w" },
	{ RISCV_INS_FCVT_S_WU, "fcvt_s_wu" },
	{ RISCV_INS_FCVT_WU_D, "fcvt_wu_d" },
	{ RISCV_INS_FCVT_WU_S, "fcvt_wu_s" },
	{ RISCV_INS_FCVT_W_D, "fcvt_w_d" },
	{ RISCV_INS_FCVT_W_S, "fcvt_w_s" },
	{ RISCV_INS_FDIV_D, "fdiv_d" },
	{ RISCV_INS_FDIV_S, "fdiv_s" },
	{ RISCV_INS_FENCE, "fence" },
	{ RISCV_INS_FENCE_I, "fence_i" },
	{ RISCV_INS_FEQ_D, "feq_d" },
	{ RISCV_INS_FEQ_S, "feq_s" },
	{ RISCV_INS_FLD, "fld" },
	{ RISCV_INS_FLE_D, "fle_d" },
	{ RISCV_INS_FLE_S, "fle_s" },
	{ RISCV_INS_FLT_D, "flt_d" },
	{ RISCV_INS_FLT_S, "flt_s" },
	{ RISCV_INS_FLW, "flw" },
	{ RISCV_INS_FMADD_D, "fmadd_d" },
	{ RISCV_INS_FMADD_S, "fmadd_s" },
	{ RISCV_INS_FMAX_D, "fmax_d" },
	{ RISCV_INS_FMAX_S, "fmax_s" },
	{ RISCV_INS_FMIN_D, "fmin_d" },
	{ RISCV_INS_FMIN_S, "fmin_s" },
	{ RISCV_INS_FMSUB_D, "fmsub_d" },
	{ RISCV_INS_FMSUB_S, "fmsub_s" },
	{ RISCV_INS_FMUL_D, "fmul_d" },
	{ RISCV_INS_FMUL_S, "fmul_s" },
	{ RISCV_INS_FMV_D_X, "fmv_d_x" },
	{ RISCV_INS_FMV_W_X, "fmv_w_x" },
	{ RISCV_INS_FMV_X_D, "fmv_x_d" },
	{ RISCV_INS_FMV_X_W, "fmv_x_w" },
	{ RISCV_INS_FNMADD_D, "fnmadd_d" },
	{ RISCV_INS_FNMADD_S, "fnmadd_s" },
	{ RISCV_INS_FNMSUB_D, "fnmsub_d" },
	{ RISCV_INS_FNMSUB_S, "fnmsub_s" },
	{ RISCV_INS_FSD, "fsd" },
	{ RISCV_INS_FSGNJN_D, "fsgnjn_d" },
	{ RISCV_INS_FSGNJN_S, "fsgnjn_s" },
	{ RISCV_INS_FSGNJX_D, "fsgnjx_d" },
	{ RISCV_INS_FSGNJX_S, "fsgnjx_s" },
	{ RISCV_INS_FSGNJ_D, "fsgnj_d" },
	{ RISCV_INS_FSGNJ_S, "fsgnj_s" },
	{ RISCV_INS_FSQRT_D, "fsqrt_d" },
	{ RISCV_INS_FSQRT_S, "fsqrt_s" },
	{ RISCV_INS_FSUB_D, "fsub_d" },
	{ RISCV_INS_FSUB_S, "fsub_s" },
	{ RISCV_INS_FSW, "fsw" },
	{ RISCV_INS_JAL, "jal" },
	{ RISCV_INS_JALR, "jalr" },
	{ RISCV_INS_LB, "lb" },
	{ RISCV_INS_LBU, "lbu" },
	{ RISCV_INS_LD, "ld" },
	{ RISCV_INS_LEA_FI, "lea_fi" },
	{ RISCV_INS_LH, "lh" },
	{ RISCV_INS_LHU, "lhu" },
	{ RISCV_INS_LR_D, "lr_d" },
	{ RISCV_INS_LR_D_AQ, "lr_d_aq" },
	{ RISCV_INS_LR_D_AQ_RL, "lr_d_aq_rl" },
	{ RISCV_INS_LR_D_RL, "lr_d_rl" },
	{ RISCV_INS_LR_W, "lr_w" },
	{ RISCV_INS_LR_W_AQ, "lr_w_aq" },
	{ RISCV_INS_LR_W_AQ_RL, "lr_w_aq_rl" },
	{ RISCV_INS_LR_W_RL, "lr_w_rl" },
	{ RISCV_INS_LUI, "lui" },
	{ RISCV_INS_LW, "lw" },
	{ RISCV_INS_LWU, "lwu" },
	{ RISCV_INS_LW_FI, "lw_fi" },
	{ RISCV_INS_MUL, "mul" },
	{ RISCV_INS_MULH, "mulh" },
	{ RISCV_INS_MULHSU, "mulhsu" },
	{ RISCV_INS_MULHU, "mulhu" },
	{ RISCV_INS_MULW, "mulw" },
	{ RISCV_INS_OR, "or" },
	{ RISCV_INS_ORI, "ori" },
	{ RISCV_INS_PseudoBR, "pseudobr" },
	{ RISCV_INS_PseudoBRIND, "pseudobrind" },
	{ RISCV_INS_PseudoCALL, "pseudocall" },
	{ RISCV_INS_PseudoRET, "pseudoret" },
	{ RISCV_INS_REM, "rem" },
	{ RISCV_INS_REMU, "remu" },
	{ RISCV_INS_REMUW, "remuw" },
	{ RISCV_INS_REMW, "remw" },
	{ RISCV_INS_SB, "sb" },
	{ RISCV_INS_SC_D, "sc_d" },
	{ RISCV_INS_SC_D_AQ, "sc_d_aq" },
	{ RISCV_INS_SC_D_AQ_RL, "sc_d_aq_rl" },
	{ RISCV_INS_SC_D_RL, "sc_d_rl" },
	{ RISCV_INS_SC_W, "sc_w" },
	{ RISCV_INS_SC_W_AQ, "sc_w_aq" },
	{ RISCV_INS_SC_W_AQ_RL, "sc_w_aq_rl" },
	{ RISCV_INS_SC_W_RL, "sc_w_rl" },
	{ RISCV_INS_SD, "sd" },
	{ RISCV_INS_SH, "sh" },
	{ RISCV_INS_SLL, "sll" },
	{ RISCV_INS_SLLI, "slli" },
	{ RISCV_INS_SLLIW, "slliw" },
	{ RISCV_INS_SLLW, "sllw" },
	{ RISCV_INS_SLT, "slt" },
	{ RISCV_INS_SLTI, "slti" },
	{ RISCV_INS_SLTIU, "sltiu" },
	{ RISCV_INS_SLTU, "sltu" },
	{ RISCV_INS_SRA, "sra" },
	{ RISCV_INS_SRAI, "srai" },
	{ RISCV_INS_SRAIW, "sraiw" },
	{ RISCV_INS_SRAW, "sraw" },
	{ RISCV_INS_SRL, "srl" },
	{ RISCV_INS_SRLI, "srli" },
	{ RISCV_INS_SRLIW, "srliw" },
	{ RISCV_INS_SRLW, "srlw" },
	{ RISCV_INS_SUB, "sub" },
	{ RISCV_INS_SUBW, "subw" },
	{ RISCV_INS_SW, "sw" },
	{ RISCV_INS_SW_FI, "sw_fi" },
	{ RISCV_INS_Select, "select" },
	{ RISCV_INS_XOR, "xor" },
	{ RISCV_INS_XORI, "xori" },
};

const char *RISCV_insn_name(csh handle, unsigned int id)
{
#ifndef CAPSTONE_DIET
	if (id >= RISCV_INS_ENDING)
		return NULL;

	return insn_name_maps[id].name;
#else
	return NULL;
#endif
}

#ifndef CAPSTONE_DIET
static const name_map group_name_maps[] = {
	// generic groups
	{ RISCV_GRP_INVALID, NULL },
	{ RISCV_GRP_JUMP, "jump" },
	{ RISCV_GRP_CALL, "call" },
	{ RISCV_GRP_RET, "ret" },
	{ RISCV_GRP_INT, "int" },
	{ RISCV_GRP_IRET, "iret" },


	// architecture-specific groups
	{ RISCV_GRP_LOAD_IMM, "load_imm" },
};
#endif

const char *RISCV_group_name(csh handle, unsigned int id)
{
#ifndef CAPSTONE_DIET
	// verify group id
	if (id >= RISCV_GRP_ENDING || (id >= RISCV_GRP_GEN_ENDING && id < RISCV_GRP_ARCH_START))
		return NULL;

	if (id >= RISCV_GRP_ARCH_START)
		return group_name_maps[id - RISCV_GRP_ARCH_START + RISCV_GRP_GEN_ENDING].name;
	else
		return group_name_maps[id].name;
#else
	return NULL;
#endif
}

// map instruction name to public instruction ID
riscv_reg RISCV_map_insn(const char *name)
{
	// handle special alias first
	unsigned int i;

	// NOTE: skip first NULL name in insn_name_maps
	i = name2id(&insn_name_maps[1], ARR_SIZE(insn_name_maps) - 1, name);

	return (i != -1)? i : RISCV_REG_INVALID;
}
#endif
