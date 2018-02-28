/* Capstone Disassembly Engine */
/* By Ben Horgan <ben.horgan@ultrasoc.com> 2018 */

#ifdef CAPSTONE_HAS_RISCV

#include "../../cs_priv.h"

static cs_err init(cs_struct *ud)
{
	/* TODO */
	return CS_ERR_OK;
}

static cs_err option(cs_struct *handle, cs_opt_type type, size_t value)
{
	/* TODO */
	return CS_ERR_OK;
}

static void destroy(cs_struct *handle)
{
}

void Riscv_enable(void)
{
	arch_init[CS_ARCH_RISCV] = init;
	arch_option[CS_ARCH_RISCV] = option;
	arch_destroy[CS_ARCH_RISCV] = destroy;
	arch_disallowed_mode_mask[CS_ARCH_X86] = ~(CS_MODE_LITTLE_ENDIAN |
		CS_MODE_32 | CS_MODE_64);

	// support this arch
	all_arch |= (1 << CS_ARCH_MIPS);
}

#endif
