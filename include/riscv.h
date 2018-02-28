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

#ifdef __cplusplus
}
#endif

#endif
