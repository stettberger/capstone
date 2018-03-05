#ifndef CS_RISCVINSTPRINTER_H
#define CS_RISCVINSTPRINTER_H

#include "../../MCInst.h"
#include "../../SStream.h"

void RISCV_printInst(MCInst *MI, SStream *O, void *info);

#endif
