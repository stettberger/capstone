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

cs_err RISCV_global_init(cs_struct *ud)
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
		ud->disasm = RISCV64_getInstruction;
	}

	return CS_ERR_OK;
}

cs_err RISCV_option(cs_struct *handle, cs_opt_type type, size_t value)
{
	if (type == CS_OPT_MODE) {
		if (value & CS_MODE_32)
			handle->disasm = RISCV_getInstruction;
		else if (value & CS_MODE_64)
		{
			handle->disasm = RISCV64_getInstruction;
		}
		else
		{
			assert(0 && "Only 32 bit and 64bit modes are implemented");
		}

		handle->mode = (cs_mode)value;
	}
	return CS_ERR_OK;
}

#endif
