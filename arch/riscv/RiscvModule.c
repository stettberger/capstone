/* Capstone Disassembly Engine */
/* By Ben Horgan <ben.horgan@ultrasoc.com> 2018 */

#ifdef CAPSTONE_HAS_RISCV

#include <assert.h>

#include "../../cs_priv.h"

#include "../../utils.h"
#include "../../MCRegisterInfo.h"
#include "RiscvDisassembler.h"
#include "RiscvInstPrinter.h"
#include "RiscvMapping.h"

static cs_err init(cs_struct *ud)
{
	MCRegisterInfo *mri;
	mri = cs_mem_malloc(sizeof(*mri));

	RISCV_init(mri);
	ud->printer = RISCV_printInst;
	ud->printer_info = mri;
	ud->getinsn_info = mri;
	ud->reg_name = RISCV_reg_name;
	ud->insn_id = RISCV_get_insn_id;
	ud->insn_name = RISCV_insn_name;
	ud->group_name = RISCV_group_name;

	if (ud->mode & CS_MODE_32)
		ud->disasm = RISCV_getInstruction;
	else
	{
		assert(0 && "64bit mode not implemented yet");
		ud->disasm = RISCV64_getInstruction;
	}

	return CS_ERR_OK;
}

static cs_err option(cs_struct *handle, cs_opt_type type, size_t value)
{
	if (type == CS_OPT_MODE) {
		if (value & CS_MODE_32)
			handle->disasm = RISCV_getInstruction;
		else
		{
			assert(0 && "64bit mode not implemented yet");
			handle->disasm = RISCV64_getInstruction;
		}

		handle->mode = (cs_mode)value;
	}
	return CS_ERR_OK;
}

static void destroy(cs_struct *handle)
{
}

void RISCV_enable(void)
{
	arch_init[CS_ARCH_RISCV] = init;
	arch_option[CS_ARCH_RISCV] = option;
	arch_destroy[CS_ARCH_RISCV] = destroy;
	arch_disallowed_mode_mask[CS_ARCH_X86] = ~(CS_MODE_LITTLE_ENDIAN |
											   CS_MODE_32); // | CS_MODE_64);

	// support this arch
	all_arch |= (1 << CS_ARCH_RISCV);
}

#endif
