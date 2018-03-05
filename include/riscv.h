#ifndef CAPSTONE_RISCV_H
#define CAPSTONE_RISCV_H

/* Capstone Disassembly Engine */
/* By Ben Horgan <ben.horgan@ultrasoc.com>, 2018 */

#ifdef __cplusplus
extern "C" {
#endif

#include "platform.h"

//> Operand type for instruction's operands
typedef enum riscv_op_type {
	RISCV_OP_INVALID = 0, // = CS_OP_INVALID (Uninitialized).
	RISCV_OP_REG, // = CS_OP_REG (Register operand).
	RISCV_OP_IMM, // = CS_OP_IMM (Immediate operand).
	RISCV_OP_MEM, // = CS_OP_MEM (Memory operand).
} riscv_op_type;

// Instruction's operand referring to memory
// This is associated with RISCV_OP_MEM operand type above
typedef struct riscv_op_mem {
	unsigned int base;	// base register
	int64_t disp;	// displacement/offset value
} riscv_op_mem;

// Instruction operand
typedef struct cs_riscv_op {
	riscv_op_type type;	// operand type
	union {
		unsigned int reg;	// register value for REG operand
		int64_t imm;		// immediate value for IMM operand
		riscv_op_mem mem;	// base/index/scale/disp value for MEM operand
	};
} cs_riscv_op;

// Instruction structure
typedef struct cs_riscv {
	// Number of operands of this instruction, 
	// or 0 when instruction has no operand.
	uint8_t op_count;
	cs_riscv_op operands[8];	// operands for this instruction.
} cs_riscv;

//> RISCV registers
typedef enum riscv_reg {
	RISCV_REG_INVALID = 0,
	RISCV_REG_X0 = 1,
	RISCV_REG_X1 = 2,
	RISCV_REG_X2 = 3,
	RISCV_REG_X3 = 4,
	RISCV_REG_X4 = 5,
	RISCV_REG_X5 = 6,
	RISCV_REG_X6 = 7,
	RISCV_REG_X7 = 8,
	RISCV_REG_X8 = 9,
	RISCV_REG_X9 = 10,
	RISCV_REG_X10 = 11,
	RISCV_REG_X11 = 12,
	RISCV_REG_X12 = 13,
	RISCV_REG_X13 = 14,
	RISCV_REG_X14 = 15,
	RISCV_REG_X15 = 16,
	RISCV_REG_X16 = 17,
	RISCV_REG_X17 = 18,
	RISCV_REG_X18 = 19,
	RISCV_REG_X19 = 20,
	RISCV_REG_X20 = 21,
	RISCV_REG_X21 = 22,
	RISCV_REG_X22 = 23,
	RISCV_REG_X23 = 24,
	RISCV_REG_X24 = 25,
	RISCV_REG_X25 = 26,
	RISCV_REG_X26 = 27,
	RISCV_REG_X27 = 28,
	RISCV_REG_X28 = 29,
	RISCV_REG_X29 = 30,
	RISCV_REG_X30 = 31,
	RISCV_REG_X31 = 32,
	RISCV_REG_F0_32 = 33,
	RISCV_REG_F0_64 = 34,
	RISCV_REG_F1_32 = 35,
	RISCV_REG_F1_64 = 36,
	RISCV_REG_F2_32 = 37,
	RISCV_REG_F2_64 = 38,
	RISCV_REG_F3_32 = 39,
	RISCV_REG_F3_64 = 40,
	RISCV_REG_F4_32 = 41,
	RISCV_REG_F4_64 = 42,
	RISCV_REG_F5_32 = 43,
	RISCV_REG_F5_64 = 44,
	RISCV_REG_F6_32 = 45,
	RISCV_REG_F6_64 = 46,
	RISCV_REG_F7_32 = 47,
	RISCV_REG_F7_64 = 48,
	RISCV_REG_F8_32 = 49,
	RISCV_REG_F8_64 = 50,
	RISCV_REG_F9_32 = 51,
	RISCV_REG_F9_64 = 52,
	RISCV_REG_F10_32 = 53,
	RISCV_REG_F10_64 = 54,
	RISCV_REG_F11_32 = 55,
	RISCV_REG_F11_64 = 56,
	RISCV_REG_F12_32 = 57,
	RISCV_REG_F12_64 = 58,
	RISCV_REG_F13_32 = 59,
	RISCV_REG_F13_64 = 60,
	RISCV_REG_F14_32 = 61,
	RISCV_REG_F14_64 = 62,
	RISCV_REG_F15_32 = 63,
	RISCV_REG_F15_64 = 64,
	RISCV_REG_F16_32 = 65,
	RISCV_REG_F16_64 = 66,
	RISCV_REG_F17_32 = 67,
	RISCV_REG_F17_64 = 68,
	RISCV_REG_F18_32 = 69,
	RISCV_REG_F18_64 = 70,
	RISCV_REG_F19_32 = 71,
	RISCV_REG_F19_64 = 72,
	RISCV_REG_F20_32 = 73,
	RISCV_REG_F20_64 = 74,
	RISCV_REG_F21_32 = 75,
	RISCV_REG_F21_64 = 76,
	RISCV_REG_F22_32 = 77,
	RISCV_REG_F22_64 = 78,
	RISCV_REG_F23_32 = 79,
	RISCV_REG_F23_64 = 80,
	RISCV_REG_F24_32 = 81,
	RISCV_REG_F24_64 = 82,
	RISCV_REG_F25_32 = 83,
	RISCV_REG_F25_64 = 84,
	RISCV_REG_F26_32 = 85,
	RISCV_REG_F26_64 = 86,
	RISCV_REG_F27_32 = 87,
	RISCV_REG_F27_64 = 88,
	RISCV_REG_F28_32 = 89,
	RISCV_REG_F28_64 = 90,
	RISCV_REG_F29_32 = 91,
	RISCV_REG_F29_64 = 92,
	RISCV_REG_F30_32 = 93,
	RISCV_REG_F30_64 = 94,
	RISCV_REG_F31_32 = 95,
	RISCV_REG_F31_64 = 96,
	RISCV_REG_ENDING,
} riscv_reg;

//> RISCV instruction
typedef enum riscv_insn {
	RISCV_INS_G_ADD,
	RISCV_INS_G_SUB,
	RISCV_INS_G_MUL,
	RISCV_INS_G_SDIV,
	RISCV_INS_G_UDIV,
	RISCV_INS_G_SREM,
	RISCV_INS_G_UREM,
	RISCV_INS_G_AND,
	RISCV_INS_G_OR,
	RISCV_INS_G_XOR,
	RISCV_INS_G_IMPLICIT_DEF,
	RISCV_INS_G_FRAME_INDEX,
	RISCV_INS_G_GLOBAL_VALUE,
	RISCV_INS_G_EXTRACT,
	RISCV_INS_G_UNMERGE_VALUES,
	RISCV_INS_G_INSERT,
	RISCV_INS_G_MERGE_VALUES,
	RISCV_INS_G_PTRTOINT,
	RISCV_INS_G_INTTOPTR,
	RISCV_INS_G_BITCAST,
	RISCV_INS_G_LOAD,
	RISCV_INS_G_STORE,
	RISCV_INS_G_BRCOND,
	RISCV_INS_G_BRINDIRECT,
	RISCV_INS_G_INTRINSIC,
	RISCV_INS_G_INTRINSIC_W_SIDE_EFFECTS,
	RISCV_INS_G_ANYEXT,
	RISCV_INS_G_TRUNC,
	RISCV_INS_G_CONSTANT,
	RISCV_INS_G_FCONSTANT,
	RISCV_INS_G_VASTART,
	RISCV_INS_G_VAARG,
	RISCV_INS_G_SEXT,
	RISCV_INS_G_ZEXT,
	RISCV_INS_G_SHL,
	RISCV_INS_G_LSHR,
	RISCV_INS_G_ASHR,
	RISCV_INS_G_ICMP,
	RISCV_INS_G_FCMP,
	RISCV_INS_G_SELECT,
	RISCV_INS_G_UADDE,
	RISCV_INS_G_USUBE,
	RISCV_INS_G_SADDO,
	RISCV_INS_G_SSUBO,
	RISCV_INS_G_UMULO,
	RISCV_INS_G_SMULO,
	RISCV_INS_G_UMULH,
	RISCV_INS_G_SMULH,
	RISCV_INS_G_FADD,
	RISCV_INS_G_FSUB,
	RISCV_INS_G_FMUL,
	RISCV_INS_G_FMA,
	RISCV_INS_G_FDIV,
	RISCV_INS_G_FREM,
	RISCV_INS_G_FPOW,
	RISCV_INS_G_FEXP,
	RISCV_INS_G_FEXP2,
	RISCV_INS_G_FLOG,
	RISCV_INS_G_FLOG2,
	RISCV_INS_G_FNEG,
	RISCV_INS_G_FPEXT,
	RISCV_INS_G_FPTRUNC,
	RISCV_INS_G_FPTOSI,
	RISCV_INS_G_FPTOUI,
	RISCV_INS_G_SITOFP,
	RISCV_INS_G_UITOFP,
	RISCV_INS_G_GEP,
	RISCV_INS_G_PTR_MASK,
	RISCV_INS_G_BR,
	RISCV_INS_G_INSERT_VECTOR_ELT,
	RISCV_INS_G_EXTRACT_VECTOR_ELT,
	RISCV_INS_G_SHUFFLE_VECTOR,
	RISCV_INS_ADD,
	RISCV_INS_ADDI,
	RISCV_INS_ADDIW,
	RISCV_INS_ADDW,
	RISCV_INS_ADJCALLSTACKDOWN,
	RISCV_INS_ADJCALLSTACKUP,
	RISCV_INS_AMOADD_D,
	RISCV_INS_AMOADD_D_AQ,
	RISCV_INS_AMOADD_D_AQ_RL,
	RISCV_INS_AMOADD_D_RL,
	RISCV_INS_AMOADD_W,
	RISCV_INS_AMOADD_W_AQ,
	RISCV_INS_AMOADD_W_AQ_RL,
	RISCV_INS_AMOADD_W_RL,
	RISCV_INS_AMOAND_D,
	RISCV_INS_AMOAND_D_AQ,
	RISCV_INS_AMOAND_D_AQ_RL,
	RISCV_INS_AMOAND_D_RL,
	RISCV_INS_AMOAND_W,
	RISCV_INS_AMOAND_W_AQ,
	RISCV_INS_AMOAND_W_AQ_RL,
	RISCV_INS_AMOAND_W_RL,
	RISCV_INS_AMOMAXU_D,
	RISCV_INS_AMOMAXU_D_AQ,
	RISCV_INS_AMOMAXU_D_AQ_RL,
	RISCV_INS_AMOMAXU_D_RL,
	RISCV_INS_AMOMAXU_W,
	RISCV_INS_AMOMAXU_W_AQ,
	RISCV_INS_AMOMAXU_W_AQ_RL,
	RISCV_INS_AMOMAXU_W_RL,
	RISCV_INS_AMOMAX_D,
	RISCV_INS_AMOMAX_D_AQ,
	RISCV_INS_AMOMAX_D_AQ_RL,
	RISCV_INS_AMOMAX_D_RL,
	RISCV_INS_AMOMAX_W,
	RISCV_INS_AMOMAX_W_AQ,
	RISCV_INS_AMOMAX_W_AQ_RL,
	RISCV_INS_AMOMAX_W_RL,
	RISCV_INS_AMOMINU_D,
	RISCV_INS_AMOMINU_D_AQ,
	RISCV_INS_AMOMINU_D_AQ_RL,
	RISCV_INS_AMOMINU_D_RL,
	RISCV_INS_AMOMINU_W,
	RISCV_INS_AMOMINU_W_AQ,
	RISCV_INS_AMOMINU_W_AQ_RL,
	RISCV_INS_AMOMINU_W_RL,
	RISCV_INS_AMOMIN_D,
	RISCV_INS_AMOMIN_D_AQ,
	RISCV_INS_AMOMIN_D_AQ_RL,
	RISCV_INS_AMOMIN_D_RL,
	RISCV_INS_AMOMIN_W,
	RISCV_INS_AMOMIN_W_AQ,
	RISCV_INS_AMOMIN_W_AQ_RL,
	RISCV_INS_AMOMIN_W_RL,
	RISCV_INS_AMOOR_D,
	RISCV_INS_AMOOR_D_AQ,
	RISCV_INS_AMOOR_D_AQ_RL,
	RISCV_INS_AMOOR_D_RL,
	RISCV_INS_AMOOR_W,
	RISCV_INS_AMOOR_W_AQ,
	RISCV_INS_AMOOR_W_AQ_RL,
	RISCV_INS_AMOOR_W_RL,
	RISCV_INS_AMOSWAP_D,
	RISCV_INS_AMOSWAP_D_AQ,
	RISCV_INS_AMOSWAP_D_AQ_RL,
	RISCV_INS_AMOSWAP_D_RL,
	RISCV_INS_AMOSWAP_W,
	RISCV_INS_AMOSWAP_W_AQ,
	RISCV_INS_AMOSWAP_W_AQ_RL,
	RISCV_INS_AMOSWAP_W_RL,
	RISCV_INS_AMOXOR_D,
	RISCV_INS_AMOXOR_D_AQ,
	RISCV_INS_AMOXOR_D_AQ_RL,
	RISCV_INS_AMOXOR_D_RL,
	RISCV_INS_AMOXOR_W,
	RISCV_INS_AMOXOR_W_AQ,
	RISCV_INS_AMOXOR_W_AQ_RL,
	RISCV_INS_AMOXOR_W_RL,
	RISCV_INS_AND,
	RISCV_INS_ANDI,
	RISCV_INS_AUIPC,
	RISCV_INS_BEQ,
	RISCV_INS_BGE,
	RISCV_INS_BGEU,
	RISCV_INS_BLT,
	RISCV_INS_BLTU,
	RISCV_INS_BNE,
	RISCV_INS_CSRRC,
	RISCV_INS_CSRRCI,
	RISCV_INS_CSRRS,
	RISCV_INS_CSRRSI,
	RISCV_INS_CSRRW,
	RISCV_INS_CSRRWI,
	RISCV_INS_DIV,
	RISCV_INS_DIVU,
	RISCV_INS_DIVUW,
	RISCV_INS_DIVW,
	RISCV_INS_EBREAK,
	RISCV_INS_ECALL,
	RISCV_INS_FADD_D,
	RISCV_INS_FADD_S,
	RISCV_INS_FCLASS_D,
	RISCV_INS_FCLASS_S,
	RISCV_INS_FCVT_D_L,
	RISCV_INS_FCVT_D_LU,
	RISCV_INS_FCVT_D_S,
	RISCV_INS_FCVT_D_W,
	RISCV_INS_FCVT_D_WU,
	RISCV_INS_FCVT_LU_D,
	RISCV_INS_FCVT_LU_S,
	RISCV_INS_FCVT_L_D,
	RISCV_INS_FCVT_L_S,
	RISCV_INS_FCVT_S_D,
	RISCV_INS_FCVT_S_L,
	RISCV_INS_FCVT_S_LU,
	RISCV_INS_FCVT_S_W,
	RISCV_INS_FCVT_S_WU,
	RISCV_INS_FCVT_WU_D,
	RISCV_INS_FCVT_WU_S,
	RISCV_INS_FCVT_W_D,
	RISCV_INS_FCVT_W_S,
	RISCV_INS_FDIV_D,
	RISCV_INS_FDIV_S,
	RISCV_INS_FENCE,
	RISCV_INS_FENCE_I,
	RISCV_INS_FEQ_D,
	RISCV_INS_FEQ_S,
	RISCV_INS_FLD,
	RISCV_INS_FLE_D,
	RISCV_INS_FLE_S,
	RISCV_INS_FLT_D,
	RISCV_INS_FLT_S,
	RISCV_INS_FLW,
	RISCV_INS_FMADD_D,
	RISCV_INS_FMADD_S,
	RISCV_INS_FMAX_D,
	RISCV_INS_FMAX_S,
	RISCV_INS_FMIN_D,
	RISCV_INS_FMIN_S,
	RISCV_INS_FMSUB_D,
	RISCV_INS_FMSUB_S,
	RISCV_INS_FMUL_D,
	RISCV_INS_FMUL_S,
	RISCV_INS_FMV_D_X,
	RISCV_INS_FMV_W_X,
	RISCV_INS_FMV_X_D,
	RISCV_INS_FMV_X_W,
	RISCV_INS_FNMADD_D,
	RISCV_INS_FNMADD_S,
	RISCV_INS_FNMSUB_D,
	RISCV_INS_FNMSUB_S,
	RISCV_INS_FSD,
	RISCV_INS_FSGNJN_D,
	RISCV_INS_FSGNJN_S,
	RISCV_INS_FSGNJX_D,
	RISCV_INS_FSGNJX_S,
	RISCV_INS_FSGNJ_D,
	RISCV_INS_FSGNJ_S,
	RISCV_INS_FSQRT_D,
	RISCV_INS_FSQRT_S,
	RISCV_INS_FSUB_D,
	RISCV_INS_FSUB_S,
	RISCV_INS_FSW,
	RISCV_INS_JAL,
	RISCV_INS_JALR,
	RISCV_INS_LB,
	RISCV_INS_LBU,
	RISCV_INS_LD,
	RISCV_INS_LEA_FI,
	RISCV_INS_LH,
	RISCV_INS_LHU,
	RISCV_INS_LR_D,
	RISCV_INS_LR_D_AQ,
	RISCV_INS_LR_D_AQ_RL,
	RISCV_INS_LR_D_RL,
	RISCV_INS_LR_W,
	RISCV_INS_LR_W_AQ,
	RISCV_INS_LR_W_AQ_RL,
	RISCV_INS_LR_W_RL,
	RISCV_INS_LUI,
	RISCV_INS_LW,
	RISCV_INS_LWU,
	RISCV_INS_LW_FI,
	RISCV_INS_MUL,
	RISCV_INS_MULH,
	RISCV_INS_MULHSU,
	RISCV_INS_MULHU,
	RISCV_INS_MULW,
	RISCV_INS_OR,
	RISCV_INS_ORI,
	RISCV_INS_PseudoBR,
	RISCV_INS_PseudoBRIND,
	RISCV_INS_PseudoCALL,
	RISCV_INS_PseudoRET,
	RISCV_INS_REM,
	RISCV_INS_REMU,
	RISCV_INS_REMUW,
	RISCV_INS_REMW,
	RISCV_INS_SB,
	RISCV_INS_SC_D,
	RISCV_INS_SC_D_AQ,
	RISCV_INS_SC_D_AQ_RL,
	RISCV_INS_SC_D_RL,
	RISCV_INS_SC_W,
	RISCV_INS_SC_W_AQ,
	RISCV_INS_SC_W_AQ_RL,
	RISCV_INS_SC_W_RL,
	RISCV_INS_SD,
	RISCV_INS_SH,
	RISCV_INS_SLL,
	RISCV_INS_SLLI,
	RISCV_INS_SLLIW,
	RISCV_INS_SLLW,
	RISCV_INS_SLT,
	RISCV_INS_SLTI,
	RISCV_INS_SLTIU,
	RISCV_INS_SLTU,
	RISCV_INS_SRA,
	RISCV_INS_SRAI,
	RISCV_INS_SRAIW,
	RISCV_INS_SRAW,
	RISCV_INS_SRL,
	RISCV_INS_SRLI,
	RISCV_INS_SRLIW,
	RISCV_INS_SRLW,
	RISCV_INS_SUB,
	RISCV_INS_SUBW,
	RISCV_INS_SW,
	RISCV_INS_SW_FI,
	RISCV_INS_Select,
	RISCV_INS_XOR,
	RISCV_INS_XORI,

	RISCV_INS_ENDING,
} riscv_insn;

//> Group of RISCV instructions
typedef enum riscv_insn_group {
	RISCV_GRP_INVALID = 0,  // uninitialized/invalid group.

	//> Generic groups
	RISCV_GRP_JUMP = CS_GRP_JUMP,    // all jump instructions (conditional+direct+indirect jumps)
	RISCV_GRP_CALL = CS_GRP_CALL,    // all call instructions
	RISCV_GRP_RET = CS_GRP_RET,     // all return instructions
	RISCV_GRP_INT = CS_GRP_INT,     // all interrupt instructions (int+syscall)
	RISCV_GRP_IRET = CS_GRP_IRET,    // all interrupt return instructions
	RISCV_GRP_GEN_ENDING,

	//> Architecture-specific groups
	RISCV_GRP_ARCH_START = 128,
	RISCV_GRP_LOAD_IMM = RISCV_GRP_ARCH_START,
	RISCV_GRP_ENDING,
} riscv_insn_group;

#ifdef __cplusplus
}
#endif

#endif
