/*===- TableGen'erated file -------------------------------------*- C++ -*-===*\
|*                                                                            *|
|*  * RISCV Disassembler                                                      *|
|*                                                                            *|
|* Automatically generated file, do not edit!                                 *|
|*                                                                            *|
\*===----------------------------------------------------------------------===*/

#include "llvm/MC/MCInst.h"
#include "llvm/Support/Debug.h"
#include "llvm/Support/DataTypes.h"
#include "llvm/Support/LEB128.h"
#include "llvm/Support/raw_ostream.h"
#include <assert.h>

namespace llvm {

// Helper function for extracting fields from encoded instructions.
template<typename InsnType>
static InsnType fieldFromInstruction(InsnType insn, unsigned startBit,
                                     unsigned numBits) {
    assert(startBit + numBits <= (sizeof(InsnType)*8) &&
           "Instruction field out of bounds!");
    InsnType fieldMask;
    if (numBits == sizeof(InsnType)*8)
      fieldMask = (InsnType)(-1LL);
    else
      fieldMask = (((InsnType)1 << numBits) - 1) << startBit;
    return (insn & fieldMask) >> startBit;
}

static const uint8_t DecoderTable32[] = {
/* 0 */       MCD::OPC_ExtractField, 0, 7,  // Inst{6-0} ...
/* 3 */       MCD::OPC_FilterValue, 3, 67, 0, // Skip to: 74
/* 7 */       MCD::OPC_ExtractField, 12, 3,  // Inst{14-12} ...
/* 10 */      MCD::OPC_FilterValue, 0, 4, 0, // Skip to: 18
/* 14 */      MCD::OPC_Decode, 139, 2, 0, // Opcode: LB
/* 18 */      MCD::OPC_FilterValue, 1, 4, 0, // Skip to: 26
/* 22 */      MCD::OPC_Decode, 143, 2, 0, // Opcode: LH
/* 26 */      MCD::OPC_FilterValue, 2, 4, 0, // Skip to: 34
/* 30 */      MCD::OPC_Decode, 154, 2, 0, // Opcode: LW
/* 34 */      MCD::OPC_FilterValue, 3, 8, 0, // Skip to: 46
/* 38 */      MCD::OPC_CheckPredicate, 0, 89, 13, // Skip to: 3459
/* 42 */      MCD::OPC_Decode, 141, 2, 0, // Opcode: LD
/* 46 */      MCD::OPC_FilterValue, 4, 4, 0, // Skip to: 54
/* 50 */      MCD::OPC_Decode, 140, 2, 0, // Opcode: LBU
/* 54 */      MCD::OPC_FilterValue, 5, 4, 0, // Skip to: 62
/* 58 */      MCD::OPC_Decode, 144, 2, 0, // Opcode: LHU
/* 62 */      MCD::OPC_FilterValue, 6, 65, 13, // Skip to: 3459
/* 66 */      MCD::OPC_CheckPredicate, 0, 61, 13, // Skip to: 3459
/* 70 */      MCD::OPC_Decode, 155, 2, 0, // Opcode: LWU
/* 74 */      MCD::OPC_FilterValue, 7, 27, 0, // Skip to: 105
/* 78 */      MCD::OPC_ExtractField, 12, 3,  // Inst{14-12} ...
/* 81 */      MCD::OPC_FilterValue, 2, 8, 0, // Skip to: 93
/* 85 */      MCD::OPC_CheckPredicate, 1, 42, 13, // Skip to: 3459
/* 89 */      MCD::OPC_Decode, 234, 1, 1, // Opcode: FLW
/* 93 */      MCD::OPC_FilterValue, 3, 34, 13, // Skip to: 3459
/* 97 */      MCD::OPC_CheckPredicate, 2, 30, 13, // Skip to: 3459
/* 101 */     MCD::OPC_Decode, 229, 1, 2, // Opcode: FLD
/* 105 */     MCD::OPC_FilterValue, 15, 31, 0, // Skip to: 140
/* 109 */     MCD::OPC_ExtractField, 7, 13,  // Inst{19-7} ...
/* 112 */     MCD::OPC_FilterValue, 0, 10, 0, // Skip to: 126
/* 116 */     MCD::OPC_CheckField, 28, 4, 0, 9, 13, // Skip to: 3459
/* 122 */     MCD::OPC_Decode, 225, 1, 3, // Opcode: FENCE
/* 126 */     MCD::OPC_FilterValue, 32, 1, 13, // Skip to: 3459
/* 130 */     MCD::OPC_CheckField, 20, 12, 0, 251, 12, // Skip to: 3459
/* 136 */     MCD::OPC_Decode, 226, 1, 4, // Opcode: FENCE_I
/* 140 */     MCD::OPC_FilterValue, 19, 87, 0, // Skip to: 231
/* 144 */     MCD::OPC_ExtractField, 12, 3,  // Inst{14-12} ...
/* 147 */     MCD::OPC_FilterValue, 0, 3, 0, // Skip to: 154
/* 151 */     MCD::OPC_Decode, 103, 0, // Opcode: ADDI
/* 154 */     MCD::OPC_FilterValue, 1, 10, 0, // Skip to: 168
/* 158 */     MCD::OPC_CheckField, 26, 6, 0, 223, 12, // Skip to: 3459
/* 164 */     MCD::OPC_Decode, 184, 2, 5, // Opcode: SLLI
/* 168 */     MCD::OPC_FilterValue, 2, 4, 0, // Skip to: 176
/* 172 */     MCD::OPC_Decode, 188, 2, 0, // Opcode: SLTI
/* 176 */     MCD::OPC_FilterValue, 3, 4, 0, // Skip to: 184
/* 180 */     MCD::OPC_Decode, 189, 2, 0, // Opcode: SLTIU
/* 184 */     MCD::OPC_FilterValue, 4, 4, 0, // Skip to: 192
/* 188 */     MCD::OPC_Decode, 205, 2, 0, // Opcode: XORI
/* 192 */     MCD::OPC_FilterValue, 5, 19, 0, // Skip to: 215
/* 196 */     MCD::OPC_ExtractField, 26, 6,  // Inst{31-26} ...
/* 199 */     MCD::OPC_FilterValue, 0, 4, 0, // Skip to: 207
/* 203 */     MCD::OPC_Decode, 196, 2, 5, // Opcode: SRLI
/* 207 */     MCD::OPC_FilterValue, 16, 176, 12, // Skip to: 3459
/* 211 */     MCD::OPC_Decode, 192, 2, 5, // Opcode: SRAI
/* 215 */     MCD::OPC_FilterValue, 6, 4, 0, // Skip to: 223
/* 219 */     MCD::OPC_Decode, 163, 2, 0, // Opcode: ORI
/* 223 */     MCD::OPC_FilterValue, 7, 160, 12, // Skip to: 3459
/* 227 */     MCD::OPC_Decode, 181, 1, 0, // Opcode: ANDI
/* 231 */     MCD::OPC_FilterValue, 23, 4, 0, // Skip to: 239
/* 235 */     MCD::OPC_Decode, 182, 1, 6, // Opcode: AUIPC
/* 239 */     MCD::OPC_FilterValue, 27, 63, 0, // Skip to: 306
/* 243 */     MCD::OPC_ExtractField, 12, 3,  // Inst{14-12} ...
/* 246 */     MCD::OPC_FilterValue, 0, 7, 0, // Skip to: 257
/* 250 */     MCD::OPC_CheckPredicate, 0, 133, 12, // Skip to: 3459
/* 254 */     MCD::OPC_Decode, 104, 0, // Opcode: ADDIW
/* 257 */     MCD::OPC_FilterValue, 1, 14, 0, // Skip to: 275
/* 261 */     MCD::OPC_CheckPredicate, 0, 122, 12, // Skip to: 3459
/* 265 */     MCD::OPC_CheckField, 25, 7, 0, 116, 12, // Skip to: 3459
/* 271 */     MCD::OPC_Decode, 185, 2, 7, // Opcode: SLLIW
/* 275 */     MCD::OPC_FilterValue, 5, 108, 12, // Skip to: 3459
/* 279 */     MCD::OPC_ExtractField, 25, 7,  // Inst{31-25} ...
/* 282 */     MCD::OPC_FilterValue, 0, 8, 0, // Skip to: 294
/* 286 */     MCD::OPC_CheckPredicate, 0, 97, 12, // Skip to: 3459
/* 290 */     MCD::OPC_Decode, 197, 2, 7, // Opcode: SRLIW
/* 294 */     MCD::OPC_FilterValue, 32, 89, 12, // Skip to: 3459
/* 298 */     MCD::OPC_CheckPredicate, 0, 85, 12, // Skip to: 3459
/* 302 */     MCD::OPC_Decode, 193, 2, 7, // Opcode: SRAIW
/* 306 */     MCD::OPC_FilterValue, 35, 39, 0, // Skip to: 349
/* 310 */     MCD::OPC_ExtractField, 12, 3,  // Inst{14-12} ...
/* 313 */     MCD::OPC_FilterValue, 0, 4, 0, // Skip to: 321
/* 317 */     MCD::OPC_Decode, 172, 2, 8, // Opcode: SB
/* 321 */     MCD::OPC_FilterValue, 1, 4, 0, // Skip to: 329
/* 325 */     MCD::OPC_Decode, 182, 2, 8, // Opcode: SH
/* 329 */     MCD::OPC_FilterValue, 2, 4, 0, // Skip to: 337
/* 333 */     MCD::OPC_Decode, 201, 2, 8, // Opcode: SW
/* 337 */     MCD::OPC_FilterValue, 3, 46, 12, // Skip to: 3459
/* 341 */     MCD::OPC_CheckPredicate, 0, 42, 12, // Skip to: 3459
/* 345 */     MCD::OPC_Decode, 181, 2, 8, // Opcode: SD
/* 349 */     MCD::OPC_FilterValue, 39, 27, 0, // Skip to: 380
/* 353 */     MCD::OPC_ExtractField, 12, 3,  // Inst{14-12} ...
/* 356 */     MCD::OPC_FilterValue, 2, 8, 0, // Skip to: 368
/* 360 */     MCD::OPC_CheckPredicate, 1, 23, 12, // Skip to: 3459
/* 364 */     MCD::OPC_Decode, 136, 2, 9, // Opcode: FSW
/* 368 */     MCD::OPC_FilterValue, 3, 15, 12, // Skip to: 3459
/* 372 */     MCD::OPC_CheckPredicate, 2, 11, 12, // Skip to: 3459
/* 376 */     MCD::OPC_Decode, 253, 1, 10, // Opcode: FSD
/* 380 */     MCD::OPC_FilterValue, 47, 115, 5, // Skip to: 1779
/* 384 */     MCD::OPC_ExtractField, 25, 7,  // Inst{31-25} ...
/* 387 */     MCD::OPC_FilterValue, 0, 25, 0, // Skip to: 416
/* 391 */     MCD::OPC_ExtractField, 12, 3,  // Inst{14-12} ...
/* 394 */     MCD::OPC_FilterValue, 2, 7, 0, // Skip to: 405
/* 398 */     MCD::OPC_CheckPredicate, 3, 241, 11, // Skip to: 3459
/* 402 */     MCD::OPC_Decode, 112, 11, // Opcode: AMOADD_W
/* 405 */     MCD::OPC_FilterValue, 3, 234, 11, // Skip to: 3459
/* 409 */     MCD::OPC_CheckPredicate, 4, 230, 11, // Skip to: 3459
/* 413 */     MCD::OPC_Decode, 108, 11, // Opcode: AMOADD_D
/* 416 */     MCD::OPC_FilterValue, 1, 25, 0, // Skip to: 445
/* 420 */     MCD::OPC_ExtractField, 12, 3,  // Inst{14-12} ...
/* 423 */     MCD::OPC_FilterValue, 2, 7, 0, // Skip to: 434
/* 427 */     MCD::OPC_CheckPredicate, 3, 212, 11, // Skip to: 3459
/* 431 */     MCD::OPC_Decode, 115, 11, // Opcode: AMOADD_W_RL
/* 434 */     MCD::OPC_FilterValue, 3, 205, 11, // Skip to: 3459
/* 438 */     MCD::OPC_CheckPredicate, 4, 201, 11, // Skip to: 3459
/* 442 */     MCD::OPC_Decode, 111, 11, // Opcode: AMOADD_D_RL
/* 445 */     MCD::OPC_FilterValue, 2, 25, 0, // Skip to: 474
/* 449 */     MCD::OPC_ExtractField, 12, 3,  // Inst{14-12} ...
/* 452 */     MCD::OPC_FilterValue, 2, 7, 0, // Skip to: 463
/* 456 */     MCD::OPC_CheckPredicate, 3, 183, 11, // Skip to: 3459
/* 460 */     MCD::OPC_Decode, 113, 11, // Opcode: AMOADD_W_AQ
/* 463 */     MCD::OPC_FilterValue, 3, 176, 11, // Skip to: 3459
/* 467 */     MCD::OPC_CheckPredicate, 4, 172, 11, // Skip to: 3459
/* 471 */     MCD::OPC_Decode, 109, 11, // Opcode: AMOADD_D_AQ
/* 474 */     MCD::OPC_FilterValue, 3, 25, 0, // Skip to: 503
/* 478 */     MCD::OPC_ExtractField, 12, 3,  // Inst{14-12} ...
/* 481 */     MCD::OPC_FilterValue, 2, 7, 0, // Skip to: 492
/* 485 */     MCD::OPC_CheckPredicate, 3, 154, 11, // Skip to: 3459
/* 489 */     MCD::OPC_Decode, 114, 11, // Opcode: AMOADD_W_AQ_RL
/* 492 */     MCD::OPC_FilterValue, 3, 147, 11, // Skip to: 3459
/* 496 */     MCD::OPC_CheckPredicate, 4, 143, 11, // Skip to: 3459
/* 500 */     MCD::OPC_Decode, 110, 11, // Opcode: AMOADD_D_AQ_RL
/* 503 */     MCD::OPC_FilterValue, 4, 27, 0, // Skip to: 534
/* 507 */     MCD::OPC_ExtractField, 12, 3,  // Inst{14-12} ...
/* 510 */     MCD::OPC_FilterValue, 2, 8, 0, // Skip to: 522
/* 514 */     MCD::OPC_CheckPredicate, 3, 125, 11, // Skip to: 3459
/* 518 */     MCD::OPC_Decode, 168, 1, 11, // Opcode: AMOSWAP_W
/* 522 */     MCD::OPC_FilterValue, 3, 117, 11, // Skip to: 3459
/* 526 */     MCD::OPC_CheckPredicate, 4, 113, 11, // Skip to: 3459
/* 530 */     MCD::OPC_Decode, 164, 1, 11, // Opcode: AMOSWAP_D
/* 534 */     MCD::OPC_FilterValue, 5, 27, 0, // Skip to: 565
/* 538 */     MCD::OPC_ExtractField, 12, 3,  // Inst{14-12} ...
/* 541 */     MCD::OPC_FilterValue, 2, 8, 0, // Skip to: 553
/* 545 */     MCD::OPC_CheckPredicate, 3, 94, 11, // Skip to: 3459
/* 549 */     MCD::OPC_Decode, 171, 1, 11, // Opcode: AMOSWAP_W_RL
/* 553 */     MCD::OPC_FilterValue, 3, 86, 11, // Skip to: 3459
/* 557 */     MCD::OPC_CheckPredicate, 4, 82, 11, // Skip to: 3459
/* 561 */     MCD::OPC_Decode, 167, 1, 11, // Opcode: AMOSWAP_D_RL
/* 565 */     MCD::OPC_FilterValue, 6, 27, 0, // Skip to: 596
/* 569 */     MCD::OPC_ExtractField, 12, 3,  // Inst{14-12} ...
/* 572 */     MCD::OPC_FilterValue, 2, 8, 0, // Skip to: 584
/* 576 */     MCD::OPC_CheckPredicate, 3, 63, 11, // Skip to: 3459
/* 580 */     MCD::OPC_Decode, 169, 1, 11, // Opcode: AMOSWAP_W_AQ
/* 584 */     MCD::OPC_FilterValue, 3, 55, 11, // Skip to: 3459
/* 588 */     MCD::OPC_CheckPredicate, 4, 51, 11, // Skip to: 3459
/* 592 */     MCD::OPC_Decode, 165, 1, 11, // Opcode: AMOSWAP_D_AQ
/* 596 */     MCD::OPC_FilterValue, 7, 27, 0, // Skip to: 627
/* 600 */     MCD::OPC_ExtractField, 12, 3,  // Inst{14-12} ...
/* 603 */     MCD::OPC_FilterValue, 2, 8, 0, // Skip to: 615
/* 607 */     MCD::OPC_CheckPredicate, 3, 32, 11, // Skip to: 3459
/* 611 */     MCD::OPC_Decode, 170, 1, 11, // Opcode: AMOSWAP_W_AQ_RL
/* 615 */     MCD::OPC_FilterValue, 3, 24, 11, // Skip to: 3459
/* 619 */     MCD::OPC_CheckPredicate, 4, 20, 11, // Skip to: 3459
/* 623 */     MCD::OPC_Decode, 166, 1, 11, // Opcode: AMOSWAP_D_AQ_RL
/* 627 */     MCD::OPC_FilterValue, 8, 39, 0, // Skip to: 670
/* 631 */     MCD::OPC_ExtractField, 12, 3,  // Inst{14-12} ...
/* 634 */     MCD::OPC_FilterValue, 2, 14, 0, // Skip to: 652
/* 638 */     MCD::OPC_CheckPredicate, 3, 1, 11, // Skip to: 3459
/* 642 */     MCD::OPC_CheckField, 20, 5, 0, 251, 10, // Skip to: 3459
/* 648 */     MCD::OPC_Decode, 149, 2, 12, // Opcode: LR_W
/* 652 */     MCD::OPC_FilterValue, 3, 243, 10, // Skip to: 3459
/* 656 */     MCD::OPC_CheckPredicate, 4, 239, 10, // Skip to: 3459
/* 660 */     MCD::OPC_CheckField, 20, 5, 0, 233, 10, // Skip to: 3459
/* 666 */     MCD::OPC_Decode, 145, 2, 12, // Opcode: LR_D
/* 670 */     MCD::OPC_FilterValue, 9, 39, 0, // Skip to: 713
/* 674 */     MCD::OPC_ExtractField, 12, 3,  // Inst{14-12} ...
/* 677 */     MCD::OPC_FilterValue, 2, 14, 0, // Skip to: 695
/* 681 */     MCD::OPC_CheckPredicate, 3, 214, 10, // Skip to: 3459
/* 685 */     MCD::OPC_CheckField, 20, 5, 0, 208, 10, // Skip to: 3459
/* 691 */     MCD::OPC_Decode, 152, 2, 12, // Opcode: LR_W_RL
/* 695 */     MCD::OPC_FilterValue, 3, 200, 10, // Skip to: 3459
/* 699 */     MCD::OPC_CheckPredicate, 4, 196, 10, // Skip to: 3459
/* 703 */     MCD::OPC_CheckField, 20, 5, 0, 190, 10, // Skip to: 3459
/* 709 */     MCD::OPC_Decode, 148, 2, 12, // Opcode: LR_D_RL
/* 713 */     MCD::OPC_FilterValue, 10, 39, 0, // Skip to: 756
/* 717 */     MCD::OPC_ExtractField, 12, 3,  // Inst{14-12} ...
/* 720 */     MCD::OPC_FilterValue, 2, 14, 0, // Skip to: 738
/* 724 */     MCD::OPC_CheckPredicate, 3, 171, 10, // Skip to: 3459
/* 728 */     MCD::OPC_CheckField, 20, 5, 0, 165, 10, // Skip to: 3459
/* 734 */     MCD::OPC_Decode, 150, 2, 12, // Opcode: LR_W_AQ
/* 738 */     MCD::OPC_FilterValue, 3, 157, 10, // Skip to: 3459
/* 742 */     MCD::OPC_CheckPredicate, 4, 153, 10, // Skip to: 3459
/* 746 */     MCD::OPC_CheckField, 20, 5, 0, 147, 10, // Skip to: 3459
/* 752 */     MCD::OPC_Decode, 146, 2, 12, // Opcode: LR_D_AQ
/* 756 */     MCD::OPC_FilterValue, 11, 39, 0, // Skip to: 799
/* 760 */     MCD::OPC_ExtractField, 12, 3,  // Inst{14-12} ...
/* 763 */     MCD::OPC_FilterValue, 2, 14, 0, // Skip to: 781
/* 767 */     MCD::OPC_CheckPredicate, 3, 128, 10, // Skip to: 3459
/* 771 */     MCD::OPC_CheckField, 20, 5, 0, 122, 10, // Skip to: 3459
/* 777 */     MCD::OPC_Decode, 151, 2, 12, // Opcode: LR_W_AQ_RL
/* 781 */     MCD::OPC_FilterValue, 3, 114, 10, // Skip to: 3459
/* 785 */     MCD::OPC_CheckPredicate, 4, 110, 10, // Skip to: 3459
/* 789 */     MCD::OPC_CheckField, 20, 5, 0, 104, 10, // Skip to: 3459
/* 795 */     MCD::OPC_Decode, 147, 2, 12, // Opcode: LR_D_AQ_RL
/* 799 */     MCD::OPC_FilterValue, 12, 27, 0, // Skip to: 830
/* 803 */     MCD::OPC_ExtractField, 12, 3,  // Inst{14-12} ...
/* 806 */     MCD::OPC_FilterValue, 2, 8, 0, // Skip to: 818
/* 810 */     MCD::OPC_CheckPredicate, 3, 85, 10, // Skip to: 3459
/* 814 */     MCD::OPC_Decode, 177, 2, 11, // Opcode: SC_W
/* 818 */     MCD::OPC_FilterValue, 3, 77, 10, // Skip to: 3459
/* 822 */     MCD::OPC_CheckPredicate, 4, 73, 10, // Skip to: 3459
/* 826 */     MCD::OPC_Decode, 173, 2, 11, // Opcode: SC_D
/* 830 */     MCD::OPC_FilterValue, 13, 27, 0, // Skip to: 861
/* 834 */     MCD::OPC_ExtractField, 12, 3,  // Inst{14-12} ...
/* 837 */     MCD::OPC_FilterValue, 2, 8, 0, // Skip to: 849
/* 841 */     MCD::OPC_CheckPredicate, 3, 54, 10, // Skip to: 3459
/* 845 */     MCD::OPC_Decode, 180, 2, 11, // Opcode: SC_W_RL
/* 849 */     MCD::OPC_FilterValue, 3, 46, 10, // Skip to: 3459
/* 853 */     MCD::OPC_CheckPredicate, 4, 42, 10, // Skip to: 3459
/* 857 */     MCD::OPC_Decode, 176, 2, 11, // Opcode: SC_D_RL
/* 861 */     MCD::OPC_FilterValue, 14, 27, 0, // Skip to: 892
/* 865 */     MCD::OPC_ExtractField, 12, 3,  // Inst{14-12} ...
/* 868 */     MCD::OPC_FilterValue, 2, 8, 0, // Skip to: 880
/* 872 */     MCD::OPC_CheckPredicate, 3, 23, 10, // Skip to: 3459
/* 876 */     MCD::OPC_Decode, 178, 2, 11, // Opcode: SC_W_AQ
/* 880 */     MCD::OPC_FilterValue, 3, 15, 10, // Skip to: 3459
/* 884 */     MCD::OPC_CheckPredicate, 4, 11, 10, // Skip to: 3459
/* 888 */     MCD::OPC_Decode, 174, 2, 11, // Opcode: SC_D_AQ
/* 892 */     MCD::OPC_FilterValue, 15, 27, 0, // Skip to: 923
/* 896 */     MCD::OPC_ExtractField, 12, 3,  // Inst{14-12} ...
/* 899 */     MCD::OPC_FilterValue, 2, 8, 0, // Skip to: 911
/* 903 */     MCD::OPC_CheckPredicate, 3, 248, 9, // Skip to: 3459
/* 907 */     MCD::OPC_Decode, 179, 2, 11, // Opcode: SC_W_AQ_RL
/* 911 */     MCD::OPC_FilterValue, 3, 240, 9, // Skip to: 3459
/* 915 */     MCD::OPC_CheckPredicate, 4, 236, 9, // Skip to: 3459
/* 919 */     MCD::OPC_Decode, 175, 2, 11, // Opcode: SC_D_AQ_RL
/* 923 */     MCD::OPC_FilterValue, 16, 27, 0, // Skip to: 954
/* 927 */     MCD::OPC_ExtractField, 12, 3,  // Inst{14-12} ...
/* 930 */     MCD::OPC_FilterValue, 2, 8, 0, // Skip to: 942
/* 934 */     MCD::OPC_CheckPredicate, 3, 217, 9, // Skip to: 3459
/* 938 */     MCD::OPC_Decode, 176, 1, 11, // Opcode: AMOXOR_W
/* 942 */     MCD::OPC_FilterValue, 3, 209, 9, // Skip to: 3459
/* 946 */     MCD::OPC_CheckPredicate, 4, 205, 9, // Skip to: 3459
/* 950 */     MCD::OPC_Decode, 172, 1, 11, // Opcode: AMOXOR_D
/* 954 */     MCD::OPC_FilterValue, 17, 27, 0, // Skip to: 985
/* 958 */     MCD::OPC_ExtractField, 12, 3,  // Inst{14-12} ...
/* 961 */     MCD::OPC_FilterValue, 2, 8, 0, // Skip to: 973
/* 965 */     MCD::OPC_CheckPredicate, 3, 186, 9, // Skip to: 3459
/* 969 */     MCD::OPC_Decode, 179, 1, 11, // Opcode: AMOXOR_W_RL
/* 973 */     MCD::OPC_FilterValue, 3, 178, 9, // Skip to: 3459
/* 977 */     MCD::OPC_CheckPredicate, 4, 174, 9, // Skip to: 3459
/* 981 */     MCD::OPC_Decode, 175, 1, 11, // Opcode: AMOXOR_D_RL
/* 985 */     MCD::OPC_FilterValue, 18, 27, 0, // Skip to: 1016
/* 989 */     MCD::OPC_ExtractField, 12, 3,  // Inst{14-12} ...
/* 992 */     MCD::OPC_FilterValue, 2, 8, 0, // Skip to: 1004
/* 996 */     MCD::OPC_CheckPredicate, 3, 155, 9, // Skip to: 3459
/* 1000 */    MCD::OPC_Decode, 177, 1, 11, // Opcode: AMOXOR_W_AQ
/* 1004 */    MCD::OPC_FilterValue, 3, 147, 9, // Skip to: 3459
/* 1008 */    MCD::OPC_CheckPredicate, 4, 143, 9, // Skip to: 3459
/* 1012 */    MCD::OPC_Decode, 173, 1, 11, // Opcode: AMOXOR_D_AQ
/* 1016 */    MCD::OPC_FilterValue, 19, 27, 0, // Skip to: 1047
/* 1020 */    MCD::OPC_ExtractField, 12, 3,  // Inst{14-12} ...
/* 1023 */    MCD::OPC_FilterValue, 2, 8, 0, // Skip to: 1035
/* 1027 */    MCD::OPC_CheckPredicate, 3, 124, 9, // Skip to: 3459
/* 1031 */    MCD::OPC_Decode, 178, 1, 11, // Opcode: AMOXOR_W_AQ_RL
/* 1035 */    MCD::OPC_FilterValue, 3, 116, 9, // Skip to: 3459
/* 1039 */    MCD::OPC_CheckPredicate, 4, 112, 9, // Skip to: 3459
/* 1043 */    MCD::OPC_Decode, 174, 1, 11, // Opcode: AMOXOR_D_AQ_RL
/* 1047 */    MCD::OPC_FilterValue, 32, 27, 0, // Skip to: 1078
/* 1051 */    MCD::OPC_ExtractField, 12, 3,  // Inst{14-12} ...
/* 1054 */    MCD::OPC_FilterValue, 2, 8, 0, // Skip to: 1066
/* 1058 */    MCD::OPC_CheckPredicate, 3, 93, 9, // Skip to: 3459
/* 1062 */    MCD::OPC_Decode, 160, 1, 11, // Opcode: AMOOR_W
/* 1066 */    MCD::OPC_FilterValue, 3, 85, 9, // Skip to: 3459
/* 1070 */    MCD::OPC_CheckPredicate, 4, 81, 9, // Skip to: 3459
/* 1074 */    MCD::OPC_Decode, 156, 1, 11, // Opcode: AMOOR_D
/* 1078 */    MCD::OPC_FilterValue, 33, 27, 0, // Skip to: 1109
/* 1082 */    MCD::OPC_ExtractField, 12, 3,  // Inst{14-12} ...
/* 1085 */    MCD::OPC_FilterValue, 2, 8, 0, // Skip to: 1097
/* 1089 */    MCD::OPC_CheckPredicate, 3, 62, 9, // Skip to: 3459
/* 1093 */    MCD::OPC_Decode, 163, 1, 11, // Opcode: AMOOR_W_RL
/* 1097 */    MCD::OPC_FilterValue, 3, 54, 9, // Skip to: 3459
/* 1101 */    MCD::OPC_CheckPredicate, 4, 50, 9, // Skip to: 3459
/* 1105 */    MCD::OPC_Decode, 159, 1, 11, // Opcode: AMOOR_D_RL
/* 1109 */    MCD::OPC_FilterValue, 34, 27, 0, // Skip to: 1140
/* 1113 */    MCD::OPC_ExtractField, 12, 3,  // Inst{14-12} ...
/* 1116 */    MCD::OPC_FilterValue, 2, 8, 0, // Skip to: 1128
/* 1120 */    MCD::OPC_CheckPredicate, 3, 31, 9, // Skip to: 3459
/* 1124 */    MCD::OPC_Decode, 161, 1, 11, // Opcode: AMOOR_W_AQ
/* 1128 */    MCD::OPC_FilterValue, 3, 23, 9, // Skip to: 3459
/* 1132 */    MCD::OPC_CheckPredicate, 4, 19, 9, // Skip to: 3459
/* 1136 */    MCD::OPC_Decode, 157, 1, 11, // Opcode: AMOOR_D_AQ
/* 1140 */    MCD::OPC_FilterValue, 35, 27, 0, // Skip to: 1171
/* 1144 */    MCD::OPC_ExtractField, 12, 3,  // Inst{14-12} ...
/* 1147 */    MCD::OPC_FilterValue, 2, 8, 0, // Skip to: 1159
/* 1151 */    MCD::OPC_CheckPredicate, 3, 0, 9, // Skip to: 3459
/* 1155 */    MCD::OPC_Decode, 162, 1, 11, // Opcode: AMOOR_W_AQ_RL
/* 1159 */    MCD::OPC_FilterValue, 3, 248, 8, // Skip to: 3459
/* 1163 */    MCD::OPC_CheckPredicate, 4, 244, 8, // Skip to: 3459
/* 1167 */    MCD::OPC_Decode, 158, 1, 11, // Opcode: AMOOR_D_AQ_RL
/* 1171 */    MCD::OPC_FilterValue, 48, 25, 0, // Skip to: 1200
/* 1175 */    MCD::OPC_ExtractField, 12, 3,  // Inst{14-12} ...
/* 1178 */    MCD::OPC_FilterValue, 2, 7, 0, // Skip to: 1189
/* 1182 */    MCD::OPC_CheckPredicate, 3, 225, 8, // Skip to: 3459
/* 1186 */    MCD::OPC_Decode, 120, 11, // Opcode: AMOAND_W
/* 1189 */    MCD::OPC_FilterValue, 3, 218, 8, // Skip to: 3459
/* 1193 */    MCD::OPC_CheckPredicate, 4, 214, 8, // Skip to: 3459
/* 1197 */    MCD::OPC_Decode, 116, 11, // Opcode: AMOAND_D
/* 1200 */    MCD::OPC_FilterValue, 49, 25, 0, // Skip to: 1229
/* 1204 */    MCD::OPC_ExtractField, 12, 3,  // Inst{14-12} ...
/* 1207 */    MCD::OPC_FilterValue, 2, 7, 0, // Skip to: 1218
/* 1211 */    MCD::OPC_CheckPredicate, 3, 196, 8, // Skip to: 3459
/* 1215 */    MCD::OPC_Decode, 123, 11, // Opcode: AMOAND_W_RL
/* 1218 */    MCD::OPC_FilterValue, 3, 189, 8, // Skip to: 3459
/* 1222 */    MCD::OPC_CheckPredicate, 4, 185, 8, // Skip to: 3459
/* 1226 */    MCD::OPC_Decode, 119, 11, // Opcode: AMOAND_D_RL
/* 1229 */    MCD::OPC_FilterValue, 50, 25, 0, // Skip to: 1258
/* 1233 */    MCD::OPC_ExtractField, 12, 3,  // Inst{14-12} ...
/* 1236 */    MCD::OPC_FilterValue, 2, 7, 0, // Skip to: 1247
/* 1240 */    MCD::OPC_CheckPredicate, 3, 167, 8, // Skip to: 3459
/* 1244 */    MCD::OPC_Decode, 121, 11, // Opcode: AMOAND_W_AQ
/* 1247 */    MCD::OPC_FilterValue, 3, 160, 8, // Skip to: 3459
/* 1251 */    MCD::OPC_CheckPredicate, 4, 156, 8, // Skip to: 3459
/* 1255 */    MCD::OPC_Decode, 117, 11, // Opcode: AMOAND_D_AQ
/* 1258 */    MCD::OPC_FilterValue, 51, 25, 0, // Skip to: 1287
/* 1262 */    MCD::OPC_ExtractField, 12, 3,  // Inst{14-12} ...
/* 1265 */    MCD::OPC_FilterValue, 2, 7, 0, // Skip to: 1276
/* 1269 */    MCD::OPC_CheckPredicate, 3, 138, 8, // Skip to: 3459
/* 1273 */    MCD::OPC_Decode, 122, 11, // Opcode: AMOAND_W_AQ_RL
/* 1276 */    MCD::OPC_FilterValue, 3, 131, 8, // Skip to: 3459
/* 1280 */    MCD::OPC_CheckPredicate, 4, 127, 8, // Skip to: 3459
/* 1284 */    MCD::OPC_Decode, 118, 11, // Opcode: AMOAND_D_AQ_RL
/* 1287 */    MCD::OPC_FilterValue, 64, 27, 0, // Skip to: 1318
/* 1291 */    MCD::OPC_ExtractField, 12, 3,  // Inst{14-12} ...
/* 1294 */    MCD::OPC_FilterValue, 2, 8, 0, // Skip to: 1306
/* 1298 */    MCD::OPC_CheckPredicate, 3, 109, 8, // Skip to: 3459
/* 1302 */    MCD::OPC_Decode, 152, 1, 11, // Opcode: AMOMIN_W
/* 1306 */    MCD::OPC_FilterValue, 3, 101, 8, // Skip to: 3459
/* 1310 */    MCD::OPC_CheckPredicate, 4, 97, 8, // Skip to: 3459
/* 1314 */    MCD::OPC_Decode, 148, 1, 11, // Opcode: AMOMIN_D
/* 1318 */    MCD::OPC_FilterValue, 65, 27, 0, // Skip to: 1349
/* 1322 */    MCD::OPC_ExtractField, 12, 3,  // Inst{14-12} ...
/* 1325 */    MCD::OPC_FilterValue, 2, 8, 0, // Skip to: 1337
/* 1329 */    MCD::OPC_CheckPredicate, 3, 78, 8, // Skip to: 3459
/* 1333 */    MCD::OPC_Decode, 155, 1, 11, // Opcode: AMOMIN_W_RL
/* 1337 */    MCD::OPC_FilterValue, 3, 70, 8, // Skip to: 3459
/* 1341 */    MCD::OPC_CheckPredicate, 4, 66, 8, // Skip to: 3459
/* 1345 */    MCD::OPC_Decode, 151, 1, 11, // Opcode: AMOMIN_D_RL
/* 1349 */    MCD::OPC_FilterValue, 66, 27, 0, // Skip to: 1380
/* 1353 */    MCD::OPC_ExtractField, 12, 3,  // Inst{14-12} ...
/* 1356 */    MCD::OPC_FilterValue, 2, 8, 0, // Skip to: 1368
/* 1360 */    MCD::OPC_CheckPredicate, 3, 47, 8, // Skip to: 3459
/* 1364 */    MCD::OPC_Decode, 153, 1, 11, // Opcode: AMOMIN_W_AQ
/* 1368 */    MCD::OPC_FilterValue, 3, 39, 8, // Skip to: 3459
/* 1372 */    MCD::OPC_CheckPredicate, 4, 35, 8, // Skip to: 3459
/* 1376 */    MCD::OPC_Decode, 149, 1, 11, // Opcode: AMOMIN_D_AQ
/* 1380 */    MCD::OPC_FilterValue, 67, 27, 0, // Skip to: 1411
/* 1384 */    MCD::OPC_ExtractField, 12, 3,  // Inst{14-12} ...
/* 1387 */    MCD::OPC_FilterValue, 2, 8, 0, // Skip to: 1399
/* 1391 */    MCD::OPC_CheckPredicate, 3, 16, 8, // Skip to: 3459
/* 1395 */    MCD::OPC_Decode, 154, 1, 11, // Opcode: AMOMIN_W_AQ_RL
/* 1399 */    MCD::OPC_FilterValue, 3, 8, 8, // Skip to: 3459
/* 1403 */    MCD::OPC_CheckPredicate, 4, 4, 8, // Skip to: 3459
/* 1407 */    MCD::OPC_Decode, 150, 1, 11, // Opcode: AMOMIN_D_AQ_RL
/* 1411 */    MCD::OPC_FilterValue, 80, 27, 0, // Skip to: 1442
/* 1415 */    MCD::OPC_ExtractField, 12, 3,  // Inst{14-12} ...
/* 1418 */    MCD::OPC_FilterValue, 2, 8, 0, // Skip to: 1430
/* 1422 */    MCD::OPC_CheckPredicate, 3, 241, 7, // Skip to: 3459
/* 1426 */    MCD::OPC_Decode, 136, 1, 11, // Opcode: AMOMAX_W
/* 1430 */    MCD::OPC_FilterValue, 3, 233, 7, // Skip to: 3459
/* 1434 */    MCD::OPC_CheckPredicate, 4, 229, 7, // Skip to: 3459
/* 1438 */    MCD::OPC_Decode, 132, 1, 11, // Opcode: AMOMAX_D
/* 1442 */    MCD::OPC_FilterValue, 81, 27, 0, // Skip to: 1473
/* 1446 */    MCD::OPC_ExtractField, 12, 3,  // Inst{14-12} ...
/* 1449 */    MCD::OPC_FilterValue, 2, 8, 0, // Skip to: 1461
/* 1453 */    MCD::OPC_CheckPredicate, 3, 210, 7, // Skip to: 3459
/* 1457 */    MCD::OPC_Decode, 139, 1, 11, // Opcode: AMOMAX_W_RL
/* 1461 */    MCD::OPC_FilterValue, 3, 202, 7, // Skip to: 3459
/* 1465 */    MCD::OPC_CheckPredicate, 4, 198, 7, // Skip to: 3459
/* 1469 */    MCD::OPC_Decode, 135, 1, 11, // Opcode: AMOMAX_D_RL
/* 1473 */    MCD::OPC_FilterValue, 82, 27, 0, // Skip to: 1504
/* 1477 */    MCD::OPC_ExtractField, 12, 3,  // Inst{14-12} ...
/* 1480 */    MCD::OPC_FilterValue, 2, 8, 0, // Skip to: 1492
/* 1484 */    MCD::OPC_CheckPredicate, 3, 179, 7, // Skip to: 3459
/* 1488 */    MCD::OPC_Decode, 137, 1, 11, // Opcode: AMOMAX_W_AQ
/* 1492 */    MCD::OPC_FilterValue, 3, 171, 7, // Skip to: 3459
/* 1496 */    MCD::OPC_CheckPredicate, 4, 167, 7, // Skip to: 3459
/* 1500 */    MCD::OPC_Decode, 133, 1, 11, // Opcode: AMOMAX_D_AQ
/* 1504 */    MCD::OPC_FilterValue, 83, 27, 0, // Skip to: 1535
/* 1508 */    MCD::OPC_ExtractField, 12, 3,  // Inst{14-12} ...
/* 1511 */    MCD::OPC_FilterValue, 2, 8, 0, // Skip to: 1523
/* 1515 */    MCD::OPC_CheckPredicate, 3, 148, 7, // Skip to: 3459
/* 1519 */    MCD::OPC_Decode, 138, 1, 11, // Opcode: AMOMAX_W_AQ_RL
/* 1523 */    MCD::OPC_FilterValue, 3, 140, 7, // Skip to: 3459
/* 1527 */    MCD::OPC_CheckPredicate, 4, 136, 7, // Skip to: 3459
/* 1531 */    MCD::OPC_Decode, 134, 1, 11, // Opcode: AMOMAX_D_AQ_RL
/* 1535 */    MCD::OPC_FilterValue, 96, 27, 0, // Skip to: 1566
/* 1539 */    MCD::OPC_ExtractField, 12, 3,  // Inst{14-12} ...
/* 1542 */    MCD::OPC_FilterValue, 2, 8, 0, // Skip to: 1554
/* 1546 */    MCD::OPC_CheckPredicate, 3, 117, 7, // Skip to: 3459
/* 1550 */    MCD::OPC_Decode, 144, 1, 11, // Opcode: AMOMINU_W
/* 1554 */    MCD::OPC_FilterValue, 3, 109, 7, // Skip to: 3459
/* 1558 */    MCD::OPC_CheckPredicate, 4, 105, 7, // Skip to: 3459
/* 1562 */    MCD::OPC_Decode, 140, 1, 11, // Opcode: AMOMINU_D
/* 1566 */    MCD::OPC_FilterValue, 97, 27, 0, // Skip to: 1597
/* 1570 */    MCD::OPC_ExtractField, 12, 3,  // Inst{14-12} ...
/* 1573 */    MCD::OPC_FilterValue, 2, 8, 0, // Skip to: 1585
/* 1577 */    MCD::OPC_CheckPredicate, 3, 86, 7, // Skip to: 3459
/* 1581 */    MCD::OPC_Decode, 147, 1, 11, // Opcode: AMOMINU_W_RL
/* 1585 */    MCD::OPC_FilterValue, 3, 78, 7, // Skip to: 3459
/* 1589 */    MCD::OPC_CheckPredicate, 4, 74, 7, // Skip to: 3459
/* 1593 */    MCD::OPC_Decode, 143, 1, 11, // Opcode: AMOMINU_D_RL
/* 1597 */    MCD::OPC_FilterValue, 98, 27, 0, // Skip to: 1628
/* 1601 */    MCD::OPC_ExtractField, 12, 3,  // Inst{14-12} ...
/* 1604 */    MCD::OPC_FilterValue, 2, 8, 0, // Skip to: 1616
/* 1608 */    MCD::OPC_CheckPredicate, 3, 55, 7, // Skip to: 3459
/* 1612 */    MCD::OPC_Decode, 145, 1, 11, // Opcode: AMOMINU_W_AQ
/* 1616 */    MCD::OPC_FilterValue, 3, 47, 7, // Skip to: 3459
/* 1620 */    MCD::OPC_CheckPredicate, 4, 43, 7, // Skip to: 3459
/* 1624 */    MCD::OPC_Decode, 141, 1, 11, // Opcode: AMOMINU_D_AQ
/* 1628 */    MCD::OPC_FilterValue, 99, 27, 0, // Skip to: 1659
/* 1632 */    MCD::OPC_ExtractField, 12, 3,  // Inst{14-12} ...
/* 1635 */    MCD::OPC_FilterValue, 2, 8, 0, // Skip to: 1647
/* 1639 */    MCD::OPC_CheckPredicate, 3, 24, 7, // Skip to: 3459
/* 1643 */    MCD::OPC_Decode, 146, 1, 11, // Opcode: AMOMINU_W_AQ_RL
/* 1647 */    MCD::OPC_FilterValue, 3, 16, 7, // Skip to: 3459
/* 1651 */    MCD::OPC_CheckPredicate, 4, 12, 7, // Skip to: 3459
/* 1655 */    MCD::OPC_Decode, 142, 1, 11, // Opcode: AMOMINU_D_AQ_RL
/* 1659 */    MCD::OPC_FilterValue, 112, 26, 0, // Skip to: 1689
/* 1663 */    MCD::OPC_ExtractField, 12, 3,  // Inst{14-12} ...
/* 1666 */    MCD::OPC_FilterValue, 2, 8, 0, // Skip to: 1678
/* 1670 */    MCD::OPC_CheckPredicate, 3, 249, 6, // Skip to: 3459
/* 1674 */    MCD::OPC_Decode, 128, 1, 11, // Opcode: AMOMAXU_W
/* 1678 */    MCD::OPC_FilterValue, 3, 241, 6, // Skip to: 3459
/* 1682 */    MCD::OPC_CheckPredicate, 4, 237, 6, // Skip to: 3459
/* 1686 */    MCD::OPC_Decode, 124, 11, // Opcode: AMOMAXU_D
/* 1689 */    MCD::OPC_FilterValue, 113, 26, 0, // Skip to: 1719
/* 1693 */    MCD::OPC_ExtractField, 12, 3,  // Inst{14-12} ...
/* 1696 */    MCD::OPC_FilterValue, 2, 8, 0, // Skip to: 1708
/* 1700 */    MCD::OPC_CheckPredicate, 3, 219, 6, // Skip to: 3459
/* 1704 */    MCD::OPC_Decode, 131, 1, 11, // Opcode: AMOMAXU_W_RL
/* 1708 */    MCD::OPC_FilterValue, 3, 211, 6, // Skip to: 3459
/* 1712 */    MCD::OPC_CheckPredicate, 4, 207, 6, // Skip to: 3459
/* 1716 */    MCD::OPC_Decode, 127, 11, // Opcode: AMOMAXU_D_RL
/* 1719 */    MCD::OPC_FilterValue, 114, 26, 0, // Skip to: 1749
/* 1723 */    MCD::OPC_ExtractField, 12, 3,  // Inst{14-12} ...
/* 1726 */    MCD::OPC_FilterValue, 2, 8, 0, // Skip to: 1738
/* 1730 */    MCD::OPC_CheckPredicate, 3, 189, 6, // Skip to: 3459
/* 1734 */    MCD::OPC_Decode, 129, 1, 11, // Opcode: AMOMAXU_W_AQ
/* 1738 */    MCD::OPC_FilterValue, 3, 181, 6, // Skip to: 3459
/* 1742 */    MCD::OPC_CheckPredicate, 4, 177, 6, // Skip to: 3459
/* 1746 */    MCD::OPC_Decode, 125, 11, // Opcode: AMOMAXU_D_AQ
/* 1749 */    MCD::OPC_FilterValue, 115, 170, 6, // Skip to: 3459
/* 1753 */    MCD::OPC_ExtractField, 12, 3,  // Inst{14-12} ...
/* 1756 */    MCD::OPC_FilterValue, 2, 8, 0, // Skip to: 1768
/* 1760 */    MCD::OPC_CheckPredicate, 3, 159, 6, // Skip to: 3459
/* 1764 */    MCD::OPC_Decode, 130, 1, 11, // Opcode: AMOMAXU_W_AQ_RL
/* 1768 */    MCD::OPC_FilterValue, 3, 151, 6, // Skip to: 3459
/* 1772 */    MCD::OPC_CheckPredicate, 4, 147, 6, // Skip to: 3459
/* 1776 */    MCD::OPC_Decode, 126, 11, // Opcode: AMOMAXU_D_AQ_RL
/* 1779 */    MCD::OPC_FilterValue, 51, 234, 0, // Skip to: 2017
/* 1783 */    MCD::OPC_ExtractField, 12, 3,  // Inst{14-12} ...
/* 1786 */    MCD::OPC_FilterValue, 0, 30, 0, // Skip to: 1820
/* 1790 */    MCD::OPC_ExtractField, 25, 7,  // Inst{31-25} ...
/* 1793 */    MCD::OPC_FilterValue, 0, 3, 0, // Skip to: 1800
/* 1797 */    MCD::OPC_Decode, 102, 11, // Opcode: ADD
/* 1800 */    MCD::OPC_FilterValue, 1, 8, 0, // Skip to: 1812
/* 1804 */    MCD::OPC_CheckPredicate, 5, 115, 6, // Skip to: 3459
/* 1808 */    MCD::OPC_Decode, 157, 2, 11, // Opcode: MUL
/* 1812 */    MCD::OPC_FilterValue, 32, 107, 6, // Skip to: 3459
/* 1816 */    MCD::OPC_Decode, 199, 2, 11, // Opcode: SUB
/* 1820 */    MCD::OPC_FilterValue, 1, 23, 0, // Skip to: 1847
/* 1824 */    MCD::OPC_ExtractField, 25, 7,  // Inst{31-25} ...
/* 1827 */    MCD::OPC_FilterValue, 0, 4, 0, // Skip to: 1835
/* 1831 */    MCD::OPC_Decode, 183, 2, 11, // Opcode: SLL
/* 1835 */    MCD::OPC_FilterValue, 1, 84, 6, // Skip to: 3459
/* 1839 */    MCD::OPC_CheckPredicate, 5, 80, 6, // Skip to: 3459
/* 1843 */    MCD::OPC_Decode, 158, 2, 11, // Opcode: MULH
/* 1847 */    MCD::OPC_FilterValue, 2, 23, 0, // Skip to: 1874
/* 1851 */    MCD::OPC_ExtractField, 25, 7,  // Inst{31-25} ...
/* 1854 */    MCD::OPC_FilterValue, 0, 4, 0, // Skip to: 1862
/* 1858 */    MCD::OPC_Decode, 187, 2, 11, // Opcode: SLT
/* 1862 */    MCD::OPC_FilterValue, 1, 57, 6, // Skip to: 3459
/* 1866 */    MCD::OPC_CheckPredicate, 5, 53, 6, // Skip to: 3459
/* 1870 */    MCD::OPC_Decode, 159, 2, 11, // Opcode: MULHSU
/* 1874 */    MCD::OPC_FilterValue, 3, 23, 0, // Skip to: 1901
/* 1878 */    MCD::OPC_ExtractField, 25, 7,  // Inst{31-25} ...
/* 1881 */    MCD::OPC_FilterValue, 0, 4, 0, // Skip to: 1889
/* 1885 */    MCD::OPC_Decode, 190, 2, 11, // Opcode: SLTU
/* 1889 */    MCD::OPC_FilterValue, 1, 30, 6, // Skip to: 3459
/* 1893 */    MCD::OPC_CheckPredicate, 5, 26, 6, // Skip to: 3459
/* 1897 */    MCD::OPC_Decode, 160, 2, 11, // Opcode: MULHU
/* 1901 */    MCD::OPC_FilterValue, 4, 23, 0, // Skip to: 1928
/* 1905 */    MCD::OPC_ExtractField, 25, 7,  // Inst{31-25} ...
/* 1908 */    MCD::OPC_FilterValue, 0, 4, 0, // Skip to: 1916
/* 1912 */    MCD::OPC_Decode, 204, 2, 11, // Opcode: XOR
/* 1916 */    MCD::OPC_FilterValue, 1, 3, 6, // Skip to: 3459
/* 1920 */    MCD::OPC_CheckPredicate, 5, 255, 5, // Skip to: 3459
/* 1924 */    MCD::OPC_Decode, 195, 1, 11, // Opcode: DIV
/* 1928 */    MCD::OPC_FilterValue, 5, 31, 0, // Skip to: 1963
/* 1932 */    MCD::OPC_ExtractField, 25, 7,  // Inst{31-25} ...
/* 1935 */    MCD::OPC_FilterValue, 0, 4, 0, // Skip to: 1943
/* 1939 */    MCD::OPC_Decode, 195, 2, 11, // Opcode: SRL
/* 1943 */    MCD::OPC_FilterValue, 1, 8, 0, // Skip to: 1955
/* 1947 */    MCD::OPC_CheckPredicate, 5, 228, 5, // Skip to: 3459
/* 1951 */    MCD::OPC_Decode, 196, 1, 11, // Opcode: DIVU
/* 1955 */    MCD::OPC_FilterValue, 32, 220, 5, // Skip to: 3459
/* 1959 */    MCD::OPC_Decode, 191, 2, 11, // Opcode: SRA
/* 1963 */    MCD::OPC_FilterValue, 6, 23, 0, // Skip to: 1990
/* 1967 */    MCD::OPC_ExtractField, 25, 7,  // Inst{31-25} ...
/* 1970 */    MCD::OPC_FilterValue, 0, 4, 0, // Skip to: 1978
/* 1974 */    MCD::OPC_Decode, 162, 2, 11, // Opcode: OR
/* 1978 */    MCD::OPC_FilterValue, 1, 197, 5, // Skip to: 3459
/* 1982 */    MCD::OPC_CheckPredicate, 5, 193, 5, // Skip to: 3459
/* 1986 */    MCD::OPC_Decode, 168, 2, 11, // Opcode: REM
/* 1990 */    MCD::OPC_FilterValue, 7, 185, 5, // Skip to: 3459
/* 1994 */    MCD::OPC_ExtractField, 25, 7,  // Inst{31-25} ...
/* 1997 */    MCD::OPC_FilterValue, 0, 4, 0, // Skip to: 2005
/* 2001 */    MCD::OPC_Decode, 180, 1, 11, // Opcode: AND
/* 2005 */    MCD::OPC_FilterValue, 1, 170, 5, // Skip to: 3459
/* 2009 */    MCD::OPC_CheckPredicate, 5, 166, 5, // Skip to: 3459
/* 2013 */    MCD::OPC_Decode, 169, 2, 11, // Opcode: REMU
/* 2017 */    MCD::OPC_FilterValue, 55, 4, 0, // Skip to: 2025
/* 2021 */    MCD::OPC_Decode, 153, 2, 6, // Opcode: LUI
/* 2025 */    MCD::OPC_FilterValue, 59, 160, 0, // Skip to: 2189
/* 2029 */    MCD::OPC_ExtractField, 12, 3,  // Inst{14-12} ...
/* 2032 */    MCD::OPC_FilterValue, 0, 38, 0, // Skip to: 2074
/* 2036 */    MCD::OPC_ExtractField, 25, 7,  // Inst{31-25} ...
/* 2039 */    MCD::OPC_FilterValue, 0, 7, 0, // Skip to: 2050
/* 2043 */    MCD::OPC_CheckPredicate, 0, 132, 5, // Skip to: 3459
/* 2047 */    MCD::OPC_Decode, 105, 11, // Opcode: ADDW
/* 2050 */    MCD::OPC_FilterValue, 1, 8, 0, // Skip to: 2062
/* 2054 */    MCD::OPC_CheckPredicate, 6, 121, 5, // Skip to: 3459
/* 2058 */    MCD::OPC_Decode, 161, 2, 11, // Opcode: MULW
/* 2062 */    MCD::OPC_FilterValue, 32, 113, 5, // Skip to: 3459
/* 2066 */    MCD::OPC_CheckPredicate, 0, 109, 5, // Skip to: 3459
/* 2070 */    MCD::OPC_Decode, 200, 2, 11, // Opcode: SUBW
/* 2074 */    MCD::OPC_FilterValue, 1, 14, 0, // Skip to: 2092
/* 2078 */    MCD::OPC_CheckPredicate, 0, 97, 5, // Skip to: 3459
/* 2082 */    MCD::OPC_CheckField, 25, 7, 0, 91, 5, // Skip to: 3459
/* 2088 */    MCD::OPC_Decode, 186, 2, 11, // Opcode: SLLW
/* 2092 */    MCD::OPC_FilterValue, 4, 14, 0, // Skip to: 2110
/* 2096 */    MCD::OPC_CheckPredicate, 6, 79, 5, // Skip to: 3459
/* 2100 */    MCD::OPC_CheckField, 25, 7, 1, 73, 5, // Skip to: 3459
/* 2106 */    MCD::OPC_Decode, 198, 1, 11, // Opcode: DIVW
/* 2110 */    MCD::OPC_FilterValue, 5, 39, 0, // Skip to: 2153
/* 2114 */    MCD::OPC_ExtractField, 25, 7,  // Inst{31-25} ...
/* 2117 */    MCD::OPC_FilterValue, 0, 8, 0, // Skip to: 2129
/* 2121 */    MCD::OPC_CheckPredicate, 0, 54, 5, // Skip to: 3459
/* 2125 */    MCD::OPC_Decode, 198, 2, 11, // Opcode: SRLW
/* 2129 */    MCD::OPC_FilterValue, 1, 8, 0, // Skip to: 2141
/* 2133 */    MCD::OPC_CheckPredicate, 6, 42, 5, // Skip to: 3459
/* 2137 */    MCD::OPC_Decode, 197, 1, 11, // Opcode: DIVUW
/* 2141 */    MCD::OPC_FilterValue, 32, 34, 5, // Skip to: 3459
/* 2145 */    MCD::OPC_CheckPredicate, 0, 30, 5, // Skip to: 3459
/* 2149 */    MCD::OPC_Decode, 194, 2, 11, // Opcode: SRAW
/* 2153 */    MCD::OPC_FilterValue, 6, 14, 0, // Skip to: 2171
/* 2157 */    MCD::OPC_CheckPredicate, 6, 18, 5, // Skip to: 3459
/* 2161 */    MCD::OPC_CheckField, 25, 7, 1, 12, 5, // Skip to: 3459
/* 2167 */    MCD::OPC_Decode, 171, 2, 11, // Opcode: REMW
/* 2171 */    MCD::OPC_FilterValue, 7, 4, 5, // Skip to: 3459
/* 2175 */    MCD::OPC_CheckPredicate, 6, 0, 5, // Skip to: 3459
/* 2179 */    MCD::OPC_CheckField, 25, 7, 1, 250, 4, // Skip to: 3459
/* 2185 */    MCD::OPC_Decode, 170, 2, 11, // Opcode: REMUW
/* 2189 */    MCD::OPC_FilterValue, 67, 39, 0, // Skip to: 2232
/* 2193 */    MCD::OPC_ExtractField, 25, 2,  // Inst{26-25} ...
/* 2196 */    MCD::OPC_FilterValue, 0, 14, 0, // Skip to: 2214
/* 2200 */    MCD::OPC_CheckPredicate, 1, 231, 4, // Skip to: 3459
/* 2204 */    MCD::OPC_CheckField, 12, 3, 7, 225, 4, // Skip to: 3459
/* 2210 */    MCD::OPC_Decode, 236, 1, 13, // Opcode: FMADD_S
/* 2214 */    MCD::OPC_FilterValue, 1, 217, 4, // Skip to: 3459
/* 2218 */    MCD::OPC_CheckPredicate, 2, 213, 4, // Skip to: 3459
/* 2222 */    MCD::OPC_CheckField, 12, 3, 7, 207, 4, // Skip to: 3459
/* 2228 */    MCD::OPC_Decode, 235, 1, 14, // Opcode: FMADD_D
/* 2232 */    MCD::OPC_FilterValue, 71, 39, 0, // Skip to: 2275
/* 2236 */    MCD::OPC_ExtractField, 25, 2,  // Inst{26-25} ...
/* 2239 */    MCD::OPC_FilterValue, 0, 14, 0, // Skip to: 2257
/* 2243 */    MCD::OPC_CheckPredicate, 1, 188, 4, // Skip to: 3459
/* 2247 */    MCD::OPC_CheckField, 12, 3, 7, 182, 4, // Skip to: 3459
/* 2253 */    MCD::OPC_Decode, 242, 1, 13, // Opcode: FMSUB_S
/* 2257 */    MCD::OPC_FilterValue, 1, 174, 4, // Skip to: 3459
/* 2261 */    MCD::OPC_CheckPredicate, 2, 170, 4, // Skip to: 3459
/* 2265 */    MCD::OPC_CheckField, 12, 3, 7, 164, 4, // Skip to: 3459
/* 2271 */    MCD::OPC_Decode, 241, 1, 14, // Opcode: FMSUB_D
/* 2275 */    MCD::OPC_FilterValue, 75, 39, 0, // Skip to: 2318
/* 2279 */    MCD::OPC_ExtractField, 25, 2,  // Inst{26-25} ...
/* 2282 */    MCD::OPC_FilterValue, 0, 14, 0, // Skip to: 2300
/* 2286 */    MCD::OPC_CheckPredicate, 1, 145, 4, // Skip to: 3459
/* 2290 */    MCD::OPC_CheckField, 12, 3, 7, 139, 4, // Skip to: 3459
/* 2296 */    MCD::OPC_Decode, 252, 1, 13, // Opcode: FNMSUB_S
/* 2300 */    MCD::OPC_FilterValue, 1, 131, 4, // Skip to: 3459
/* 2304 */    MCD::OPC_CheckPredicate, 2, 127, 4, // Skip to: 3459
/* 2308 */    MCD::OPC_CheckField, 12, 3, 7, 121, 4, // Skip to: 3459
/* 2314 */    MCD::OPC_Decode, 251, 1, 14, // Opcode: FNMSUB_D
/* 2318 */    MCD::OPC_FilterValue, 79, 39, 0, // Skip to: 2361
/* 2322 */    MCD::OPC_ExtractField, 25, 2,  // Inst{26-25} ...
/* 2325 */    MCD::OPC_FilterValue, 0, 14, 0, // Skip to: 2343
/* 2329 */    MCD::OPC_CheckPredicate, 1, 102, 4, // Skip to: 3459
/* 2333 */    MCD::OPC_CheckField, 12, 3, 7, 96, 4, // Skip to: 3459
/* 2339 */    MCD::OPC_Decode, 250, 1, 13, // Opcode: FNMADD_S
/* 2343 */    MCD::OPC_FilterValue, 1, 88, 4, // Skip to: 3459
/* 2347 */    MCD::OPC_CheckPredicate, 2, 84, 4, // Skip to: 3459
/* 2351 */    MCD::OPC_CheckField, 12, 3, 7, 78, 4, // Skip to: 3459
/* 2357 */    MCD::OPC_Decode, 249, 1, 14, // Opcode: FNMADD_D
/* 2361 */    MCD::OPC_FilterValue, 83, 159, 3, // Skip to: 3292
/* 2365 */    MCD::OPC_ExtractField, 25, 7,  // Inst{31-25} ...
/* 2368 */    MCD::OPC_FilterValue, 0, 14, 0, // Skip to: 2386
/* 2372 */    MCD::OPC_CheckPredicate, 1, 59, 4, // Skip to: 3459
/* 2376 */    MCD::OPC_CheckField, 12, 3, 7, 53, 4, // Skip to: 3459
/* 2382 */    MCD::OPC_Decode, 202, 1, 15, // Opcode: FADD_S
/* 2386 */    MCD::OPC_FilterValue, 1, 14, 0, // Skip to: 2404
/* 2390 */    MCD::OPC_CheckPredicate, 2, 41, 4, // Skip to: 3459
/* 2394 */    MCD::OPC_CheckField, 12, 3, 7, 35, 4, // Skip to: 3459
/* 2400 */    MCD::OPC_Decode, 201, 1, 16, // Opcode: FADD_D
/* 2404 */    MCD::OPC_FilterValue, 4, 14, 0, // Skip to: 2422
/* 2408 */    MCD::OPC_CheckPredicate, 1, 23, 4, // Skip to: 3459
/* 2412 */    MCD::OPC_CheckField, 12, 3, 7, 17, 4, // Skip to: 3459
/* 2418 */    MCD::OPC_Decode, 135, 2, 15, // Opcode: FSUB_S
/* 2422 */    MCD::OPC_FilterValue, 5, 14, 0, // Skip to: 2440
/* 2426 */    MCD::OPC_CheckPredicate, 2, 5, 4, // Skip to: 3459
/* 2430 */    MCD::OPC_CheckField, 12, 3, 7, 255, 3, // Skip to: 3459
/* 2436 */    MCD::OPC_Decode, 134, 2, 16, // Opcode: FSUB_D
/* 2440 */    MCD::OPC_FilterValue, 8, 14, 0, // Skip to: 2458
/* 2444 */    MCD::OPC_CheckPredicate, 1, 243, 3, // Skip to: 3459
/* 2448 */    MCD::OPC_CheckField, 12, 3, 7, 237, 3, // Skip to: 3459
/* 2454 */    MCD::OPC_Decode, 244, 1, 15, // Opcode: FMUL_S
/* 2458 */    MCD::OPC_FilterValue, 9, 14, 0, // Skip to: 2476
/* 2462 */    MCD::OPC_CheckPredicate, 2, 225, 3, // Skip to: 3459
/* 2466 */    MCD::OPC_CheckField, 12, 3, 7, 219, 3, // Skip to: 3459
/* 2472 */    MCD::OPC_Decode, 243, 1, 16, // Opcode: FMUL_D
/* 2476 */    MCD::OPC_FilterValue, 12, 14, 0, // Skip to: 2494
/* 2480 */    MCD::OPC_CheckPredicate, 1, 207, 3, // Skip to: 3459
/* 2484 */    MCD::OPC_CheckField, 12, 3, 7, 201, 3, // Skip to: 3459
/* 2490 */    MCD::OPC_Decode, 224, 1, 15, // Opcode: FDIV_S
/* 2494 */    MCD::OPC_FilterValue, 13, 14, 0, // Skip to: 2512
/* 2498 */    MCD::OPC_CheckPredicate, 2, 189, 3, // Skip to: 3459
/* 2502 */    MCD::OPC_CheckField, 12, 3, 7, 183, 3, // Skip to: 3459
/* 2508 */    MCD::OPC_Decode, 223, 1, 16, // Opcode: FDIV_D
/* 2512 */    MCD::OPC_FilterValue, 16, 39, 0, // Skip to: 2555
/* 2516 */    MCD::OPC_ExtractField, 12, 3,  // Inst{14-12} ...
/* 2519 */    MCD::OPC_FilterValue, 0, 8, 0, // Skip to: 2531
/* 2523 */    MCD::OPC_CheckPredicate, 1, 164, 3, // Skip to: 3459
/* 2527 */    MCD::OPC_Decode, 131, 2, 15, // Opcode: FSGNJ_S
/* 2531 */    MCD::OPC_FilterValue, 1, 8, 0, // Skip to: 2543
/* 2535 */    MCD::OPC_CheckPredicate, 1, 152, 3, // Skip to: 3459
/* 2539 */    MCD::OPC_Decode, 255, 1, 15, // Opcode: FSGNJN_S
/* 2543 */    MCD::OPC_FilterValue, 2, 144, 3, // Skip to: 3459
/* 2547 */    MCD::OPC_CheckPredicate, 1, 140, 3, // Skip to: 3459
/* 2551 */    MCD::OPC_Decode, 129, 2, 15, // Opcode: FSGNJX_S
/* 2555 */    MCD::OPC_FilterValue, 17, 39, 0, // Skip to: 2598
/* 2559 */    MCD::OPC_ExtractField, 12, 3,  // Inst{14-12} ...
/* 2562 */    MCD::OPC_FilterValue, 0, 8, 0, // Skip to: 2574
/* 2566 */    MCD::OPC_CheckPredicate, 2, 121, 3, // Skip to: 3459
/* 2570 */    MCD::OPC_Decode, 130, 2, 16, // Opcode: FSGNJ_D
/* 2574 */    MCD::OPC_FilterValue, 1, 8, 0, // Skip to: 2586
/* 2578 */    MCD::OPC_CheckPredicate, 2, 109, 3, // Skip to: 3459
/* 2582 */    MCD::OPC_Decode, 254, 1, 16, // Opcode: FSGNJN_D
/* 2586 */    MCD::OPC_FilterValue, 2, 101, 3, // Skip to: 3459
/* 2590 */    MCD::OPC_CheckPredicate, 2, 97, 3, // Skip to: 3459
/* 2594 */    MCD::OPC_Decode, 128, 2, 16, // Opcode: FSGNJX_D
/* 2598 */    MCD::OPC_FilterValue, 20, 27, 0, // Skip to: 2629
/* 2602 */    MCD::OPC_ExtractField, 12, 3,  // Inst{14-12} ...
/* 2605 */    MCD::OPC_FilterValue, 0, 8, 0, // Skip to: 2617
/* 2609 */    MCD::OPC_CheckPredicate, 1, 78, 3, // Skip to: 3459
/* 2613 */    MCD::OPC_Decode, 240, 1, 15, // Opcode: FMIN_S
/* 2617 */    MCD::OPC_FilterValue, 1, 70, 3, // Skip to: 3459
/* 2621 */    MCD::OPC_CheckPredicate, 1, 66, 3, // Skip to: 3459
/* 2625 */    MCD::OPC_Decode, 238, 1, 15, // Opcode: FMAX_S
/* 2629 */    MCD::OPC_FilterValue, 21, 27, 0, // Skip to: 2660
/* 2633 */    MCD::OPC_ExtractField, 12, 3,  // Inst{14-12} ...
/* 2636 */    MCD::OPC_FilterValue, 0, 8, 0, // Skip to: 2648
/* 2640 */    MCD::OPC_CheckPredicate, 2, 47, 3, // Skip to: 3459
/* 2644 */    MCD::OPC_Decode, 239, 1, 16, // Opcode: FMIN_D
/* 2648 */    MCD::OPC_FilterValue, 1, 39, 3, // Skip to: 3459
/* 2652 */    MCD::OPC_CheckPredicate, 2, 35, 3, // Skip to: 3459
/* 2656 */    MCD::OPC_Decode, 237, 1, 16, // Opcode: FMAX_D
/* 2660 */    MCD::OPC_FilterValue, 32, 20, 0, // Skip to: 2684
/* 2664 */    MCD::OPC_CheckPredicate, 2, 23, 3, // Skip to: 3459
/* 2668 */    MCD::OPC_CheckField, 20, 5, 1, 17, 3, // Skip to: 3459
/* 2674 */    MCD::OPC_CheckField, 12, 3, 7, 11, 3, // Skip to: 3459
/* 2680 */    MCD::OPC_Decode, 214, 1, 17, // Opcode: FCVT_S_D
/* 2684 */    MCD::OPC_FilterValue, 33, 20, 0, // Skip to: 2708
/* 2688 */    MCD::OPC_CheckPredicate, 2, 255, 2, // Skip to: 3459
/* 2692 */    MCD::OPC_CheckField, 20, 5, 0, 249, 2, // Skip to: 3459
/* 2698 */    MCD::OPC_CheckField, 12, 3, 0, 243, 2, // Skip to: 3459
/* 2704 */    MCD::OPC_Decode, 207, 1, 18, // Opcode: FCVT_D_S
/* 2708 */    MCD::OPC_FilterValue, 44, 20, 0, // Skip to: 2732
/* 2712 */    MCD::OPC_CheckPredicate, 1, 231, 2, // Skip to: 3459
/* 2716 */    MCD::OPC_CheckField, 20, 5, 0, 225, 2, // Skip to: 3459
/* 2722 */    MCD::OPC_CheckField, 12, 3, 7, 219, 2, // Skip to: 3459
/* 2728 */    MCD::OPC_Decode, 133, 2, 19, // Opcode: FSQRT_S
/* 2732 */    MCD::OPC_FilterValue, 45, 20, 0, // Skip to: 2756
/* 2736 */    MCD::OPC_CheckPredicate, 2, 207, 2, // Skip to: 3459
/* 2740 */    MCD::OPC_CheckField, 20, 5, 0, 201, 2, // Skip to: 3459
/* 2746 */    MCD::OPC_CheckField, 12, 3, 7, 195, 2, // Skip to: 3459
/* 2752 */    MCD::OPC_Decode, 132, 2, 20, // Opcode: FSQRT_D
/* 2756 */    MCD::OPC_FilterValue, 80, 39, 0, // Skip to: 2799
/* 2760 */    MCD::OPC_ExtractField, 12, 3,  // Inst{14-12} ...
/* 2763 */    MCD::OPC_FilterValue, 0, 8, 0, // Skip to: 2775
/* 2767 */    MCD::OPC_CheckPredicate, 1, 176, 2, // Skip to: 3459
/* 2771 */    MCD::OPC_Decode, 231, 1, 21, // Opcode: FLE_S
/* 2775 */    MCD::OPC_FilterValue, 1, 8, 0, // Skip to: 2787
/* 2779 */    MCD::OPC_CheckPredicate, 1, 164, 2, // Skip to: 3459
/* 2783 */    MCD::OPC_Decode, 233, 1, 21, // Opcode: FLT_S
/* 2787 */    MCD::OPC_FilterValue, 2, 156, 2, // Skip to: 3459
/* 2791 */    MCD::OPC_CheckPredicate, 1, 152, 2, // Skip to: 3459
/* 2795 */    MCD::OPC_Decode, 228, 1, 21, // Opcode: FEQ_S
/* 2799 */    MCD::OPC_FilterValue, 81, 39, 0, // Skip to: 2842
/* 2803 */    MCD::OPC_ExtractField, 12, 3,  // Inst{14-12} ...
/* 2806 */    MCD::OPC_FilterValue, 0, 8, 0, // Skip to: 2818
/* 2810 */    MCD::OPC_CheckPredicate, 2, 133, 2, // Skip to: 3459
/* 2814 */    MCD::OPC_Decode, 230, 1, 22, // Opcode: FLE_D
/* 2818 */    MCD::OPC_FilterValue, 1, 8, 0, // Skip to: 2830
/* 2822 */    MCD::OPC_CheckPredicate, 2, 121, 2, // Skip to: 3459
/* 2826 */    MCD::OPC_Decode, 232, 1, 22, // Opcode: FLT_D
/* 2830 */    MCD::OPC_FilterValue, 2, 113, 2, // Skip to: 3459
/* 2834 */    MCD::OPC_CheckPredicate, 2, 109, 2, // Skip to: 3459
/* 2838 */    MCD::OPC_Decode, 227, 1, 22, // Opcode: FEQ_D
/* 2842 */    MCD::OPC_FilterValue, 96, 75, 0, // Skip to: 2921
/* 2846 */    MCD::OPC_ExtractField, 20, 5,  // Inst{24-20} ...
/* 2849 */    MCD::OPC_FilterValue, 0, 14, 0, // Skip to: 2867
/* 2853 */    MCD::OPC_CheckPredicate, 1, 90, 2, // Skip to: 3459
/* 2857 */    MCD::OPC_CheckField, 12, 3, 7, 84, 2, // Skip to: 3459
/* 2863 */    MCD::OPC_Decode, 222, 1, 23, // Opcode: FCVT_W_S
/* 2867 */    MCD::OPC_FilterValue, 1, 14, 0, // Skip to: 2885
/* 2871 */    MCD::OPC_CheckPredicate, 1, 72, 2, // Skip to: 3459
/* 2875 */    MCD::OPC_CheckField, 12, 3, 7, 66, 2, // Skip to: 3459
/* 2881 */    MCD::OPC_Decode, 220, 1, 23, // Opcode: FCVT_WU_S
/* 2885 */    MCD::OPC_FilterValue, 2, 14, 0, // Skip to: 2903
/* 2889 */    MCD::OPC_CheckPredicate, 7, 54, 2, // Skip to: 3459
/* 2893 */    MCD::OPC_CheckField, 12, 3, 7, 48, 2, // Skip to: 3459
/* 2899 */    MCD::OPC_Decode, 213, 1, 23, // Opcode: FCVT_L_S
/* 2903 */    MCD::OPC_FilterValue, 3, 40, 2, // Skip to: 3459
/* 2907 */    MCD::OPC_CheckPredicate, 7, 36, 2, // Skip to: 3459
/* 2911 */    MCD::OPC_CheckField, 12, 3, 7, 30, 2, // Skip to: 3459
/* 2917 */    MCD::OPC_Decode, 211, 1, 23, // Opcode: FCVT_LU_S
/* 2921 */    MCD::OPC_FilterValue, 97, 75, 0, // Skip to: 3000
/* 2925 */    MCD::OPC_ExtractField, 20, 5,  // Inst{24-20} ...
/* 2928 */    MCD::OPC_FilterValue, 0, 14, 0, // Skip to: 2946
/* 2932 */    MCD::OPC_CheckPredicate, 2, 11, 2, // Skip to: 3459
/* 2936 */    MCD::OPC_CheckField, 12, 3, 7, 5, 2, // Skip to: 3459
/* 2942 */    MCD::OPC_Decode, 221, 1, 24, // Opcode: FCVT_W_D
/* 2946 */    MCD::OPC_FilterValue, 1, 14, 0, // Skip to: 2964
/* 2950 */    MCD::OPC_CheckPredicate, 2, 249, 1, // Skip to: 3459
/* 2954 */    MCD::OPC_CheckField, 12, 3, 7, 243, 1, // Skip to: 3459
/* 2960 */    MCD::OPC_Decode, 219, 1, 24, // Opcode: FCVT_WU_D
/* 2964 */    MCD::OPC_FilterValue, 2, 14, 0, // Skip to: 2982
/* 2968 */    MCD::OPC_CheckPredicate, 8, 231, 1, // Skip to: 3459
/* 2972 */    MCD::OPC_CheckField, 12, 3, 7, 225, 1, // Skip to: 3459
/* 2978 */    MCD::OPC_Decode, 212, 1, 24, // Opcode: FCVT_L_D
/* 2982 */    MCD::OPC_FilterValue, 3, 217, 1, // Skip to: 3459
/* 2986 */    MCD::OPC_CheckPredicate, 8, 213, 1, // Skip to: 3459
/* 2990 */    MCD::OPC_CheckField, 12, 3, 7, 207, 1, // Skip to: 3459
/* 2996 */    MCD::OPC_Decode, 210, 1, 24, // Opcode: FCVT_LU_D
/* 3000 */    MCD::OPC_FilterValue, 104, 75, 0, // Skip to: 3079
/* 3004 */    MCD::OPC_ExtractField, 20, 5,  // Inst{24-20} ...
/* 3007 */    MCD::OPC_FilterValue, 0, 14, 0, // Skip to: 3025
/* 3011 */    MCD::OPC_CheckPredicate, 1, 188, 1, // Skip to: 3459
/* 3015 */    MCD::OPC_CheckField, 12, 3, 7, 182, 1, // Skip to: 3459
/* 3021 */    MCD::OPC_Decode, 217, 1, 25, // Opcode: FCVT_S_W
/* 3025 */    MCD::OPC_FilterValue, 1, 14, 0, // Skip to: 3043
/* 3029 */    MCD::OPC_CheckPredicate, 1, 170, 1, // Skip to: 3459
/* 3033 */    MCD::OPC_CheckField, 12, 3, 7, 164, 1, // Skip to: 3459
/* 3039 */    MCD::OPC_Decode, 218, 1, 25, // Opcode: FCVT_S_WU
/* 3043 */    MCD::OPC_FilterValue, 2, 14, 0, // Skip to: 3061
/* 3047 */    MCD::OPC_CheckPredicate, 7, 152, 1, // Skip to: 3459
/* 3051 */    MCD::OPC_CheckField, 12, 3, 7, 146, 1, // Skip to: 3459
/* 3057 */    MCD::OPC_Decode, 215, 1, 25, // Opcode: FCVT_S_L
/* 3061 */    MCD::OPC_FilterValue, 3, 138, 1, // Skip to: 3459
/* 3065 */    MCD::OPC_CheckPredicate, 7, 134, 1, // Skip to: 3459
/* 3069 */    MCD::OPC_CheckField, 12, 3, 7, 128, 1, // Skip to: 3459
/* 3075 */    MCD::OPC_Decode, 216, 1, 25, // Opcode: FCVT_S_LU
/* 3079 */    MCD::OPC_FilterValue, 105, 75, 0, // Skip to: 3158
/* 3083 */    MCD::OPC_ExtractField, 20, 5,  // Inst{24-20} ...
/* 3086 */    MCD::OPC_FilterValue, 0, 14, 0, // Skip to: 3104
/* 3090 */    MCD::OPC_CheckPredicate, 2, 109, 1, // Skip to: 3459
/* 3094 */    MCD::OPC_CheckField, 12, 3, 0, 103, 1, // Skip to: 3459
/* 3100 */    MCD::OPC_Decode, 208, 1, 26, // Opcode: FCVT_D_W
/* 3104 */    MCD::OPC_FilterValue, 1, 14, 0, // Skip to: 3122
/* 3108 */    MCD::OPC_CheckPredicate, 2, 91, 1, // Skip to: 3459
/* 3112 */    MCD::OPC_CheckField, 12, 3, 0, 85, 1, // Skip to: 3459
/* 3118 */    MCD::OPC_Decode, 209, 1, 26, // Opcode: FCVT_D_WU
/* 3122 */    MCD::OPC_FilterValue, 2, 14, 0, // Skip to: 3140
/* 3126 */    MCD::OPC_CheckPredicate, 8, 73, 1, // Skip to: 3459
/* 3130 */    MCD::OPC_CheckField, 12, 3, 0, 67, 1, // Skip to: 3459
/* 3136 */    MCD::OPC_Decode, 205, 1, 26, // Opcode: FCVT_D_L
/* 3140 */    MCD::OPC_FilterValue, 3, 59, 1, // Skip to: 3459
/* 3144 */    MCD::OPC_CheckPredicate, 8, 55, 1, // Skip to: 3459
/* 3148 */    MCD::OPC_CheckField, 12, 3, 0, 49, 1, // Skip to: 3459
/* 3154 */    MCD::OPC_Decode, 206, 1, 26, // Opcode: FCVT_D_LU
/* 3158 */    MCD::OPC_FilterValue, 112, 39, 0, // Skip to: 3201
/* 3162 */    MCD::OPC_ExtractField, 12, 3,  // Inst{14-12} ...
/* 3165 */    MCD::OPC_FilterValue, 0, 14, 0, // Skip to: 3183
/* 3169 */    MCD::OPC_CheckPredicate, 1, 30, 1, // Skip to: 3459
/* 3173 */    MCD::OPC_CheckField, 20, 5, 0, 24, 1, // Skip to: 3459
/* 3179 */    MCD::OPC_Decode, 248, 1, 23, // Opcode: FMV_X_W
/* 3183 */    MCD::OPC_FilterValue, 1, 16, 1, // Skip to: 3459
/* 3187 */    MCD::OPC_CheckPredicate, 1, 12, 1, // Skip to: 3459
/* 3191 */    MCD::OPC_CheckField, 20, 5, 0, 6, 1, // Skip to: 3459
/* 3197 */    MCD::OPC_Decode, 204, 1, 23, // Opcode: FCLASS_S
/* 3201 */    MCD::OPC_FilterValue, 113, 39, 0, // Skip to: 3244
/* 3205 */    MCD::OPC_ExtractField, 12, 3,  // Inst{14-12} ...
/* 3208 */    MCD::OPC_FilterValue, 0, 14, 0, // Skip to: 3226
/* 3212 */    MCD::OPC_CheckPredicate, 8, 243, 0, // Skip to: 3459
/* 3216 */    MCD::OPC_CheckField, 20, 5, 0, 237, 0, // Skip to: 3459
/* 3222 */    MCD::OPC_Decode, 247, 1, 24, // Opcode: FMV_X_D
/* 3226 */    MCD::OPC_FilterValue, 1, 229, 0, // Skip to: 3459
/* 3230 */    MCD::OPC_CheckPredicate, 2, 225, 0, // Skip to: 3459
/* 3234 */    MCD::OPC_CheckField, 20, 5, 0, 219, 0, // Skip to: 3459
/* 3240 */    MCD::OPC_Decode, 203, 1, 24, // Opcode: FCLASS_D
/* 3244 */    MCD::OPC_FilterValue, 120, 20, 0, // Skip to: 3268
/* 3248 */    MCD::OPC_CheckPredicate, 1, 207, 0, // Skip to: 3459
/* 3252 */    MCD::OPC_CheckField, 20, 5, 0, 201, 0, // Skip to: 3459
/* 3258 */    MCD::OPC_CheckField, 12, 3, 0, 195, 0, // Skip to: 3459
/* 3264 */    MCD::OPC_Decode, 246, 1, 25, // Opcode: FMV_W_X
/* 3268 */    MCD::OPC_FilterValue, 121, 187, 0, // Skip to: 3459
/* 3272 */    MCD::OPC_CheckPredicate, 8, 183, 0, // Skip to: 3459
/* 3276 */    MCD::OPC_CheckField, 20, 5, 0, 177, 0, // Skip to: 3459
/* 3282 */    MCD::OPC_CheckField, 12, 3, 0, 171, 0, // Skip to: 3459
/* 3288 */    MCD::OPC_Decode, 245, 1, 26, // Opcode: FMV_D_X
/* 3292 */    MCD::OPC_FilterValue, 99, 51, 0, // Skip to: 3347
/* 3296 */    MCD::OPC_ExtractField, 12, 3,  // Inst{14-12} ...
/* 3299 */    MCD::OPC_FilterValue, 0, 4, 0, // Skip to: 3307
/* 3303 */    MCD::OPC_Decode, 183, 1, 27, // Opcode: BEQ
/* 3307 */    MCD::OPC_FilterValue, 1, 4, 0, // Skip to: 3315
/* 3311 */    MCD::OPC_Decode, 188, 1, 27, // Opcode: BNE
/* 3315 */    MCD::OPC_FilterValue, 4, 4, 0, // Skip to: 3323
/* 3319 */    MCD::OPC_Decode, 186, 1, 27, // Opcode: BLT
/* 3323 */    MCD::OPC_FilterValue, 5, 4, 0, // Skip to: 3331
/* 3327 */    MCD::OPC_Decode, 184, 1, 27, // Opcode: BGE
/* 3331 */    MCD::OPC_FilterValue, 6, 4, 0, // Skip to: 3339
/* 3335 */    MCD::OPC_Decode, 187, 1, 27, // Opcode: BLTU
/* 3339 */    MCD::OPC_FilterValue, 7, 116, 0, // Skip to: 3459
/* 3343 */    MCD::OPC_Decode, 185, 1, 27, // Opcode: BGEU
/* 3347 */    MCD::OPC_FilterValue, 103, 10, 0, // Skip to: 3361
/* 3351 */    MCD::OPC_CheckField, 12, 3, 0, 102, 0, // Skip to: 3459
/* 3357 */    MCD::OPC_Decode, 138, 2, 0, // Opcode: JALR
/* 3361 */    MCD::OPC_FilterValue, 111, 4, 0, // Skip to: 3369
/* 3365 */    MCD::OPC_Decode, 137, 2, 28, // Opcode: JAL
/* 3369 */    MCD::OPC_FilterValue, 115, 86, 0, // Skip to: 3459
/* 3373 */    MCD::OPC_ExtractField, 12, 3,  // Inst{14-12} ...
/* 3376 */    MCD::OPC_FilterValue, 0, 31, 0, // Skip to: 3411
/* 3380 */    MCD::OPC_ExtractField, 15, 17,  // Inst{31-15} ...
/* 3383 */    MCD::OPC_FilterValue, 0, 10, 0, // Skip to: 3397
/* 3387 */    MCD::OPC_CheckField, 7, 5, 0, 66, 0, // Skip to: 3459
/* 3393 */    MCD::OPC_Decode, 200, 1, 4, // Opcode: ECALL
/* 3397 */    MCD::OPC_FilterValue, 32, 58, 0, // Skip to: 3459
/* 3401 */    MCD::OPC_CheckField, 7, 5, 0, 52, 0, // Skip to: 3459
/* 3407 */    MCD::OPC_Decode, 199, 1, 4, // Opcode: EBREAK
/* 3411 */    MCD::OPC_FilterValue, 1, 4, 0, // Skip to: 3419
/* 3415 */    MCD::OPC_Decode, 193, 1, 29, // Opcode: CSRRW
/* 3419 */    MCD::OPC_FilterValue, 2, 4, 0, // Skip to: 3427
/* 3423 */    MCD::OPC_Decode, 191, 1, 29, // Opcode: CSRRS
/* 3427 */    MCD::OPC_FilterValue, 3, 4, 0, // Skip to: 3435
/* 3431 */    MCD::OPC_Decode, 189, 1, 29, // Opcode: CSRRC
/* 3435 */    MCD::OPC_FilterValue, 5, 4, 0, // Skip to: 3443
/* 3439 */    MCD::OPC_Decode, 194, 1, 30, // Opcode: CSRRWI
/* 3443 */    MCD::OPC_FilterValue, 6, 4, 0, // Skip to: 3451
/* 3447 */    MCD::OPC_Decode, 192, 1, 30, // Opcode: CSRRSI
/* 3451 */    MCD::OPC_FilterValue, 7, 4, 0, // Skip to: 3459
/* 3455 */    MCD::OPC_Decode, 190, 1, 30, // Opcode: CSRRCI
/* 3459 */    MCD::OPC_Fail,
  0
};

static bool checkDecoderPredicate(unsigned Idx, const FeatureBitset& Bits) {
  switch (Idx) {
  default: llvm_unreachable("Invalid index!");
  case 0:
    return (Bits[RISCV::Feature64Bit]);
  case 1:
    return (Bits[RISCV::FeatureStdExtF]);
  case 2:
    return (Bits[RISCV::FeatureStdExtD]);
  case 3:
    return (Bits[RISCV::FeatureStdExtA]);
  case 4:
    return (Bits[RISCV::FeatureStdExtA] && Bits[RISCV::Feature64Bit]);
  case 5:
    return (Bits[RISCV::FeatureStdExtM]);
  case 6:
    return (Bits[RISCV::FeatureStdExtM] && Bits[RISCV::Feature64Bit]);
  case 7:
    return (Bits[RISCV::FeatureStdExtF] && Bits[RISCV::Feature64Bit]);
  case 8:
    return (Bits[RISCV::FeatureStdExtD] && Bits[RISCV::Feature64Bit]);
  }
}

template<typename InsnType>
static DecodeStatus decodeToMCInst(DecodeStatus S, unsigned Idx, InsnType insn, MCInst &MI,
                                   uint64_t Address, const void *Decoder, bool &DecodeComplete) {
  DecodeComplete = true;
  InsnType tmp;
  switch (Idx) {
  default: llvm_unreachable("Invalid index!");
  case 0:
    tmp = fieldFromInstruction(insn, 7, 5);
    if (DecodeGPRRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler::Fail) { return MCDisassembler::Fail; }
    tmp = fieldFromInstruction(insn, 15, 5);
    if (DecodeGPRRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler::Fail) { return MCDisassembler::Fail; }
    tmp = fieldFromInstruction(insn, 20, 12);
    if (decodeSImmOperand<12>(MI, tmp, Address, Decoder) == MCDisassembler::Fail) { return MCDisassembler::Fail; }
    return S;
  case 1:
    tmp = fieldFromInstruction(insn, 7, 5);
    if (DecodeFPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler::Fail) { return MCDisassembler::Fail; }
    tmp = fieldFromInstruction(insn, 15, 5);
    if (DecodeGPRRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler::Fail) { return MCDisassembler::Fail; }
    tmp = fieldFromInstruction(insn, 20, 12);
    if (decodeSImmOperand<12>(MI, tmp, Address, Decoder) == MCDisassembler::Fail) { return MCDisassembler::Fail; }
    return S;
  case 2:
    tmp = fieldFromInstruction(insn, 7, 5);
    if (DecodeFPR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler::Fail) { return MCDisassembler::Fail; }
    tmp = fieldFromInstruction(insn, 15, 5);
    if (DecodeGPRRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler::Fail) { return MCDisassembler::Fail; }
    tmp = fieldFromInstruction(insn, 20, 12);
    if (decodeSImmOperand<12>(MI, tmp, Address, Decoder) == MCDisassembler::Fail) { return MCDisassembler::Fail; }
    return S;
  case 3:
    tmp = fieldFromInstruction(insn, 24, 4);
    if (decodeUImmOperand<4>(MI, tmp, Address, Decoder) == MCDisassembler::Fail) { return MCDisassembler::Fail; }
    tmp = fieldFromInstruction(insn, 20, 4);
    if (decodeUImmOperand<4>(MI, tmp, Address, Decoder) == MCDisassembler::Fail) { return MCDisassembler::Fail; }
    return S;
  case 4:
    return S;
  case 5:
    tmp = fieldFromInstruction(insn, 7, 5);
    if (DecodeGPRRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler::Fail) { return MCDisassembler::Fail; }
    tmp = fieldFromInstruction(insn, 15, 5);
    if (DecodeGPRRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler::Fail) { return MCDisassembler::Fail; }
    tmp = fieldFromInstruction(insn, 20, 6);
    if (decodeUImmOperand<6>(MI, tmp, Address, Decoder) == MCDisassembler::Fail) { return MCDisassembler::Fail; }
    return S;
  case 6:
    tmp = fieldFromInstruction(insn, 7, 5);
    if (DecodeGPRRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler::Fail) { return MCDisassembler::Fail; }
    tmp = fieldFromInstruction(insn, 12, 20);
    if (decodeUImmOperand<20>(MI, tmp, Address, Decoder) == MCDisassembler::Fail) { return MCDisassembler::Fail; }
    return S;
  case 7:
    tmp = fieldFromInstruction(insn, 7, 5);
    if (DecodeGPRRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler::Fail) { return MCDisassembler::Fail; }
    tmp = fieldFromInstruction(insn, 15, 5);
    if (DecodeGPRRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler::Fail) { return MCDisassembler::Fail; }
    tmp = fieldFromInstruction(insn, 20, 5);
    if (decodeUImmOperand<5>(MI, tmp, Address, Decoder) == MCDisassembler::Fail) { return MCDisassembler::Fail; }
    return S;
  case 8:
    tmp = fieldFromInstruction(insn, 20, 5);
    if (DecodeGPRRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler::Fail) { return MCDisassembler::Fail; }
    tmp = fieldFromInstruction(insn, 15, 5);
    if (DecodeGPRRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler::Fail) { return MCDisassembler::Fail; }
    tmp = 0;
    tmp |= fieldFromInstruction(insn, 7, 5) << 0;
    tmp |= fieldFromInstruction(insn, 25, 7) << 5;
    if (decodeSImmOperand<12>(MI, tmp, Address, Decoder) == MCDisassembler::Fail) { return MCDisassembler::Fail; }
    return S;
  case 9:
    tmp = fieldFromInstruction(insn, 20, 5);
    if (DecodeFPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler::Fail) { return MCDisassembler::Fail; }
    tmp = fieldFromInstruction(insn, 15, 5);
    if (DecodeGPRRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler::Fail) { return MCDisassembler::Fail; }
    tmp = 0;
    tmp |= fieldFromInstruction(insn, 7, 5) << 0;
    tmp |= fieldFromInstruction(insn, 25, 7) << 5;
    if (decodeSImmOperand<12>(MI, tmp, Address, Decoder) == MCDisassembler::Fail) { return MCDisassembler::Fail; }
    return S;
  case 10:
    tmp = fieldFromInstruction(insn, 20, 5);
    if (DecodeFPR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler::Fail) { return MCDisassembler::Fail; }
    tmp = fieldFromInstruction(insn, 15, 5);
    if (DecodeGPRRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler::Fail) { return MCDisassembler::Fail; }
    tmp = 0;
    tmp |= fieldFromInstruction(insn, 7, 5) << 0;
    tmp |= fieldFromInstruction(insn, 25, 7) << 5;
    if (decodeSImmOperand<12>(MI, tmp, Address, Decoder) == MCDisassembler::Fail) { return MCDisassembler::Fail; }
    return S;
  case 11:
    tmp = fieldFromInstruction(insn, 7, 5);
    if (DecodeGPRRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler::Fail) { return MCDisassembler::Fail; }
    tmp = fieldFromInstruction(insn, 15, 5);
    if (DecodeGPRRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler::Fail) { return MCDisassembler::Fail; }
    tmp = fieldFromInstruction(insn, 20, 5);
    if (DecodeGPRRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler::Fail) { return MCDisassembler::Fail; }
    return S;
  case 12:
    tmp = fieldFromInstruction(insn, 7, 5);
    if (DecodeGPRRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler::Fail) { return MCDisassembler::Fail; }
    tmp = fieldFromInstruction(insn, 15, 5);
    if (DecodeGPRRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler::Fail) { return MCDisassembler::Fail; }
    return S;
  case 13:
    tmp = fieldFromInstruction(insn, 7, 5);
    if (DecodeFPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler::Fail) { return MCDisassembler::Fail; }
    tmp = fieldFromInstruction(insn, 15, 5);
    if (DecodeFPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler::Fail) { return MCDisassembler::Fail; }
    tmp = fieldFromInstruction(insn, 20, 5);
    if (DecodeFPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler::Fail) { return MCDisassembler::Fail; }
    tmp = fieldFromInstruction(insn, 27, 5);
    if (DecodeFPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler::Fail) { return MCDisassembler::Fail; }
    return S;
  case 14:
    tmp = fieldFromInstruction(insn, 7, 5);
    if (DecodeFPR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler::Fail) { return MCDisassembler::Fail; }
    tmp = fieldFromInstruction(insn, 15, 5);
    if (DecodeFPR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler::Fail) { return MCDisassembler::Fail; }
    tmp = fieldFromInstruction(insn, 20, 5);
    if (DecodeFPR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler::Fail) { return MCDisassembler::Fail; }
    tmp = fieldFromInstruction(insn, 27, 5);
    if (DecodeFPR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler::Fail) { return MCDisassembler::Fail; }
    return S;
  case 15:
    tmp = fieldFromInstruction(insn, 7, 5);
    if (DecodeFPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler::Fail) { return MCDisassembler::Fail; }
    tmp = fieldFromInstruction(insn, 15, 5);
    if (DecodeFPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler::Fail) { return MCDisassembler::Fail; }
    tmp = fieldFromInstruction(insn, 20, 5);
    if (DecodeFPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler::Fail) { return MCDisassembler::Fail; }
    return S;
  case 16:
    tmp = fieldFromInstruction(insn, 7, 5);
    if (DecodeFPR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler::Fail) { return MCDisassembler::Fail; }
    tmp = fieldFromInstruction(insn, 15, 5);
    if (DecodeFPR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler::Fail) { return MCDisassembler::Fail; }
    tmp = fieldFromInstruction(insn, 20, 5);
    if (DecodeFPR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler::Fail) { return MCDisassembler::Fail; }
    return S;
  case 17:
    tmp = fieldFromInstruction(insn, 7, 5);
    if (DecodeFPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler::Fail) { return MCDisassembler::Fail; }
    tmp = fieldFromInstruction(insn, 15, 5);
    if (DecodeFPR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler::Fail) { return MCDisassembler::Fail; }
    return S;
  case 18:
    tmp = fieldFromInstruction(insn, 7, 5);
    if (DecodeFPR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler::Fail) { return MCDisassembler::Fail; }
    tmp = fieldFromInstruction(insn, 15, 5);
    if (DecodeFPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler::Fail) { return MCDisassembler::Fail; }
    return S;
  case 19:
    tmp = fieldFromInstruction(insn, 7, 5);
    if (DecodeFPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler::Fail) { return MCDisassembler::Fail; }
    tmp = fieldFromInstruction(insn, 15, 5);
    if (DecodeFPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler::Fail) { return MCDisassembler::Fail; }
    return S;
  case 20:
    tmp = fieldFromInstruction(insn, 7, 5);
    if (DecodeFPR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler::Fail) { return MCDisassembler::Fail; }
    tmp = fieldFromInstruction(insn, 15, 5);
    if (DecodeFPR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler::Fail) { return MCDisassembler::Fail; }
    return S;
  case 21:
    tmp = fieldFromInstruction(insn, 7, 5);
    if (DecodeGPRRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler::Fail) { return MCDisassembler::Fail; }
    tmp = fieldFromInstruction(insn, 15, 5);
    if (DecodeFPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler::Fail) { return MCDisassembler::Fail; }
    tmp = fieldFromInstruction(insn, 20, 5);
    if (DecodeFPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler::Fail) { return MCDisassembler::Fail; }
    return S;
  case 22:
    tmp = fieldFromInstruction(insn, 7, 5);
    if (DecodeGPRRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler::Fail) { return MCDisassembler::Fail; }
    tmp = fieldFromInstruction(insn, 15, 5);
    if (DecodeFPR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler::Fail) { return MCDisassembler::Fail; }
    tmp = fieldFromInstruction(insn, 20, 5);
    if (DecodeFPR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler::Fail) { return MCDisassembler::Fail; }
    return S;
  case 23:
    tmp = fieldFromInstruction(insn, 7, 5);
    if (DecodeGPRRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler::Fail) { return MCDisassembler::Fail; }
    tmp = fieldFromInstruction(insn, 15, 5);
    if (DecodeFPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler::Fail) { return MCDisassembler::Fail; }
    return S;
  case 24:
    tmp = fieldFromInstruction(insn, 7, 5);
    if (DecodeGPRRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler::Fail) { return MCDisassembler::Fail; }
    tmp = fieldFromInstruction(insn, 15, 5);
    if (DecodeFPR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler::Fail) { return MCDisassembler::Fail; }
    return S;
  case 25:
    tmp = fieldFromInstruction(insn, 7, 5);
    if (DecodeFPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler::Fail) { return MCDisassembler::Fail; }
    tmp = fieldFromInstruction(insn, 15, 5);
    if (DecodeGPRRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler::Fail) { return MCDisassembler::Fail; }
    return S;
  case 26:
    tmp = fieldFromInstruction(insn, 7, 5);
    if (DecodeFPR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler::Fail) { return MCDisassembler::Fail; }
    tmp = fieldFromInstruction(insn, 15, 5);
    if (DecodeGPRRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler::Fail) { return MCDisassembler::Fail; }
    return S;
  case 27:
    tmp = fieldFromInstruction(insn, 15, 5);
    if (DecodeGPRRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler::Fail) { return MCDisassembler::Fail; }
    tmp = fieldFromInstruction(insn, 20, 5);
    if (DecodeGPRRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler::Fail) { return MCDisassembler::Fail; }
    tmp = 0;
    tmp |= fieldFromInstruction(insn, 7, 1) << 10;
    tmp |= fieldFromInstruction(insn, 8, 4) << 0;
    tmp |= fieldFromInstruction(insn, 25, 6) << 4;
    tmp |= fieldFromInstruction(insn, 31, 1) << 11;
    if (decodeSImmOperandAndLsl1<13>(MI, tmp, Address, Decoder) == MCDisassembler::Fail) { return MCDisassembler::Fail; }
    return S;
  case 28:
    tmp = fieldFromInstruction(insn, 7, 5);
    if (DecodeGPRRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler::Fail) { return MCDisassembler::Fail; }
    tmp = 0;
    tmp |= fieldFromInstruction(insn, 12, 8) << 11;
    tmp |= fieldFromInstruction(insn, 20, 1) << 10;
    tmp |= fieldFromInstruction(insn, 21, 10) << 0;
    tmp |= fieldFromInstruction(insn, 31, 1) << 19;
    if (decodeSImmOperandAndLsl1<21>(MI, tmp, Address, Decoder) == MCDisassembler::Fail) { return MCDisassembler::Fail; }
    return S;
  case 29:
    tmp = fieldFromInstruction(insn, 7, 5);
    if (DecodeGPRRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler::Fail) { return MCDisassembler::Fail; }
    tmp = fieldFromInstruction(insn, 20, 12);
    if (decodeUImmOperand<12>(MI, tmp, Address, Decoder) == MCDisassembler::Fail) { return MCDisassembler::Fail; }
    tmp = fieldFromInstruction(insn, 15, 5);
    if (DecodeGPRRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler::Fail) { return MCDisassembler::Fail; }
    return S;
  case 30:
    tmp = fieldFromInstruction(insn, 7, 5);
    if (DecodeGPRRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler::Fail) { return MCDisassembler::Fail; }
    tmp = fieldFromInstruction(insn, 20, 12);
    if (decodeUImmOperand<12>(MI, tmp, Address, Decoder) == MCDisassembler::Fail) { return MCDisassembler::Fail; }
    tmp = fieldFromInstruction(insn, 15, 5);
    if (decodeUImmOperand<5>(MI, tmp, Address, Decoder) == MCDisassembler::Fail) { return MCDisassembler::Fail; }
    return S;
  }
}

template<typename InsnType>
static DecodeStatus decodeInstruction(const uint8_t DecodeTable[], MCInst &MI,
                                      InsnType insn, uint64_t Address,
                                      const void *DisAsm,
                                      const MCSubtargetInfo &STI) {
  const FeatureBitset& Bits = STI.getFeatureBits();

  const uint8_t *Ptr = DecodeTable;
  uint32_t CurFieldValue = 0;
  DecodeStatus S = MCDisassembler::Success;
  while (true) {
    ptrdiff_t Loc = Ptr - DecodeTable;
    switch (*Ptr) {
    default:
      errs() << Loc << ": Unexpected decode table opcode!\n";
      return MCDisassembler::Fail;
    case MCD::OPC_ExtractField: {
      unsigned Start = *++Ptr;
      unsigned Len = *++Ptr;
      ++Ptr;
      CurFieldValue = fieldFromInstruction(insn, Start, Len);
      DEBUG(dbgs() << Loc << ": OPC_ExtractField(" << Start << ", "
                   << Len << "): " << CurFieldValue << "\n");
      break;
    }
    case MCD::OPC_FilterValue: {
      // Decode the field value.
      unsigned Len;
      InsnType Val = decodeULEB128(++Ptr, &Len);
      Ptr += Len;
      // NumToSkip is a plain 16-bit integer.
      unsigned NumToSkip = *Ptr++;
      NumToSkip |= (*Ptr++) << 8;

      // Perform the filter operation.
      if (Val != CurFieldValue)
        Ptr += NumToSkip;
      DEBUG(dbgs() << Loc << ": OPC_FilterValue(" << Val << ", " << NumToSkip
                   << "): " << ((Val != CurFieldValue) ? "FAIL:" : "PASS:")
                   << " continuing at " << (Ptr - DecodeTable) << "\n");

      break;
    }
    case MCD::OPC_CheckField: {
      unsigned Start = *++Ptr;
      unsigned Len = *++Ptr;
      InsnType FieldValue = fieldFromInstruction(insn, Start, Len);
      // Decode the field value.
      uint32_t ExpectedValue = decodeULEB128(++Ptr, &Len);
      Ptr += Len;
      // NumToSkip is a plain 16-bit integer.
      unsigned NumToSkip = *Ptr++;
      NumToSkip |= (*Ptr++) << 8;

      // If the actual and expected values don't match, skip.
      if (ExpectedValue != FieldValue)
        Ptr += NumToSkip;
      DEBUG(dbgs() << Loc << ": OPC_CheckField(" << Start << ", "
                   << Len << ", " << ExpectedValue << ", " << NumToSkip
                   << "): FieldValue = " << FieldValue << ", ExpectedValue = "
                   << ExpectedValue << ": "
                   << ((ExpectedValue == FieldValue) ? "PASS\n" : "FAIL\n"));
      break;
    }
    case MCD::OPC_CheckPredicate: {
      unsigned Len;
      // Decode the Predicate Index value.
      unsigned PIdx = decodeULEB128(++Ptr, &Len);
      Ptr += Len;
      // NumToSkip is a plain 16-bit integer.
      unsigned NumToSkip = *Ptr++;
      NumToSkip |= (*Ptr++) << 8;
      // Check the predicate.
      bool Pred;
      if (!(Pred = checkDecoderPredicate(PIdx, Bits)))
        Ptr += NumToSkip;
      (void)Pred;
      DEBUG(dbgs() << Loc << ": OPC_CheckPredicate(" << PIdx << "): "
            << (Pred ? "PASS\n" : "FAIL\n"));

      break;
    }
    case MCD::OPC_Decode: {
      unsigned Len;
      // Decode the Opcode value.
      unsigned Opc = decodeULEB128(++Ptr, &Len);
      Ptr += Len;
      unsigned DecodeIdx = decodeULEB128(Ptr, &Len);
      Ptr += Len;

      MI.clear();
      MI.setOpcode(Opc);
      bool DecodeComplete;
      S = decodeToMCInst(S, DecodeIdx, insn, MI, Address, DisAsm, DecodeComplete);
      assert(DecodeComplete);

      DEBUG(dbgs() << Loc << ": OPC_Decode: opcode " << Opc
                   << ", using decoder " << DecodeIdx << ": "
                   << (S != MCDisassembler::Fail ? "PASS" : "FAIL") << "\n");
      return S;
    }
    case MCD::OPC_TryDecode: {
      unsigned Len;
      // Decode the Opcode value.
      unsigned Opc = decodeULEB128(++Ptr, &Len);
      Ptr += Len;
      unsigned DecodeIdx = decodeULEB128(Ptr, &Len);
      Ptr += Len;
      // NumToSkip is a plain 16-bit integer.
      unsigned NumToSkip = *Ptr++;
      NumToSkip |= (*Ptr++) << 8;

      // Perform the decode operation.
      MCInst TmpMI;
      TmpMI.setOpcode(Opc);
      bool DecodeComplete;
      S = decodeToMCInst(S, DecodeIdx, insn, TmpMI, Address, DisAsm, DecodeComplete);
      DEBUG(dbgs() << Loc << ": OPC_TryDecode: opcode " << Opc
                   << ", using decoder " << DecodeIdx << ": ");

      if (DecodeComplete) {
        // Decoding complete.
        DEBUG(dbgs() << (S != MCDisassembler::Fail ? "PASS" : "FAIL") << "\n");
        MI = TmpMI;
        return S;
      } else {
        assert(S == MCDisassembler::Fail);
        // If the decoding was incomplete, skip.
        Ptr += NumToSkip;
        DEBUG(dbgs() << "FAIL: continuing at " << (Ptr - DecodeTable) << "\n");
        // Reset decode status. This also drops a SoftFail status that could be
        // set before the decode attempt.
        S = MCDisassembler::Success;
      }
      break;
    }
    case MCD::OPC_SoftFail: {
      // Decode the mask values.
      unsigned Len;
      InsnType PositiveMask = decodeULEB128(++Ptr, &Len);
      Ptr += Len;
      InsnType NegativeMask = decodeULEB128(Ptr, &Len);
      Ptr += Len;
      bool Fail = (insn & PositiveMask) || (~insn & NegativeMask);
      if (Fail)
        S = MCDisassembler::SoftFail;
      DEBUG(dbgs() << Loc << ": OPC_SoftFail: " << (Fail ? "FAIL\n":"PASS\n"));
      break;
    }
    case MCD::OPC_Fail: {
      DEBUG(dbgs() << Loc << ": OPC_Fail\n");
      return MCDisassembler::Fail;
    }
    }
  }
  llvm_unreachable("bogosity detected in disassembler state machine!");
}


} // End llvm namespace
