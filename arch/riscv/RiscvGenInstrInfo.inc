/*===- TableGen'erated file -------------------------------------*- C++ -*-===*\
|*                                                                            *|
|* Target Instruction Enum Values and Descriptors                             *|
|*                                                                            *|
|* Automatically generated file, do not edit!                                 *|
|*                                                                            *|
\*===----------------------------------------------------------------------===*/

#ifdef GET_INSTRINFO_ENUM
#undef GET_INSTRINFO_ENUM
namespace llvm {

namespace RISCV {
  enum {
    PHI	= 0,
    INLINEASM	= 1,
    CFI_INSTRUCTION	= 2,
    EH_LABEL	= 3,
    GC_LABEL	= 4,
    KILL	= 5,
    EXTRACT_SUBREG	= 6,
    INSERT_SUBREG	= 7,
    IMPLICIT_DEF	= 8,
    SUBREG_TO_REG	= 9,
    COPY_TO_REGCLASS	= 10,
    DBG_VALUE	= 11,
    REG_SEQUENCE	= 12,
    COPY	= 13,
    BUNDLE	= 14,
    LIFETIME_START	= 15,
    LIFETIME_END	= 16,
    STACKMAP	= 17,
    FENTRY_CALL	= 18,
    PATCHPOINT	= 19,
    LOAD_STACK_GUARD	= 20,
    STATEPOINT	= 21,
    LOCAL_ESCAPE	= 22,
    FAULTING_OP	= 23,
    PATCHABLE_OP	= 24,
    PATCHABLE_FUNCTION_ENTER	= 25,
    PATCHABLE_RET	= 26,
    PATCHABLE_FUNCTION_EXIT	= 27,
    PATCHABLE_TAIL_CALL	= 28,
    PATCHABLE_EVENT_CALL	= 29,
    G_ADD	= 30,
    G_SUB	= 31,
    G_MUL	= 32,
    G_SDIV	= 33,
    G_UDIV	= 34,
    G_SREM	= 35,
    G_UREM	= 36,
    G_AND	= 37,
    G_OR	= 38,
    G_XOR	= 39,
    G_IMPLICIT_DEF	= 40,
    G_FRAME_INDEX	= 41,
    G_GLOBAL_VALUE	= 42,
    G_EXTRACT	= 43,
    G_UNMERGE_VALUES	= 44,
    G_INSERT	= 45,
    G_MERGE_VALUES	= 46,
    G_PTRTOINT	= 47,
    G_INTTOPTR	= 48,
    G_BITCAST	= 49,
    G_LOAD	= 50,
    G_STORE	= 51,
    G_BRCOND	= 52,
    G_BRINDIRECT	= 53,
    G_INTRINSIC	= 54,
    G_INTRINSIC_W_SIDE_EFFECTS	= 55,
    G_ANYEXT	= 56,
    G_TRUNC	= 57,
    G_CONSTANT	= 58,
    G_FCONSTANT	= 59,
    G_VASTART	= 60,
    G_VAARG	= 61,
    G_SEXT	= 62,
    G_ZEXT	= 63,
    G_SHL	= 64,
    G_LSHR	= 65,
    G_ASHR	= 66,
    G_ICMP	= 67,
    G_FCMP	= 68,
    G_SELECT	= 69,
    G_UADDE	= 70,
    G_USUBE	= 71,
    G_SADDO	= 72,
    G_SSUBO	= 73,
    G_UMULO	= 74,
    G_SMULO	= 75,
    G_UMULH	= 76,
    G_SMULH	= 77,
    G_FADD	= 78,
    G_FSUB	= 79,
    G_FMUL	= 80,
    G_FMA	= 81,
    G_FDIV	= 82,
    G_FREM	= 83,
    G_FPOW	= 84,
    G_FEXP	= 85,
    G_FEXP2	= 86,
    G_FLOG	= 87,
    G_FLOG2	= 88,
    G_FNEG	= 89,
    G_FPEXT	= 90,
    G_FPTRUNC	= 91,
    G_FPTOSI	= 92,
    G_FPTOUI	= 93,
    G_SITOFP	= 94,
    G_UITOFP	= 95,
    G_GEP	= 96,
    G_PTR_MASK	= 97,
    G_BR	= 98,
    G_INSERT_VECTOR_ELT	= 99,
    G_EXTRACT_VECTOR_ELT	= 100,
    G_SHUFFLE_VECTOR	= 101,
    ADD	= 102,
    ADDI	= 103,
    ADDIW	= 104,
    ADDW	= 105,
    ADJCALLSTACKDOWN	= 106,
    ADJCALLSTACKUP	= 107,
    AMOADD_D	= 108,
    AMOADD_D_AQ	= 109,
    AMOADD_D_AQ_RL	= 110,
    AMOADD_D_RL	= 111,
    AMOADD_W	= 112,
    AMOADD_W_AQ	= 113,
    AMOADD_W_AQ_RL	= 114,
    AMOADD_W_RL	= 115,
    AMOAND_D	= 116,
    AMOAND_D_AQ	= 117,
    AMOAND_D_AQ_RL	= 118,
    AMOAND_D_RL	= 119,
    AMOAND_W	= 120,
    AMOAND_W_AQ	= 121,
    AMOAND_W_AQ_RL	= 122,
    AMOAND_W_RL	= 123,
    AMOMAXU_D	= 124,
    AMOMAXU_D_AQ	= 125,
    AMOMAXU_D_AQ_RL	= 126,
    AMOMAXU_D_RL	= 127,
    AMOMAXU_W	= 128,
    AMOMAXU_W_AQ	= 129,
    AMOMAXU_W_AQ_RL	= 130,
    AMOMAXU_W_RL	= 131,
    AMOMAX_D	= 132,
    AMOMAX_D_AQ	= 133,
    AMOMAX_D_AQ_RL	= 134,
    AMOMAX_D_RL	= 135,
    AMOMAX_W	= 136,
    AMOMAX_W_AQ	= 137,
    AMOMAX_W_AQ_RL	= 138,
    AMOMAX_W_RL	= 139,
    AMOMINU_D	= 140,
    AMOMINU_D_AQ	= 141,
    AMOMINU_D_AQ_RL	= 142,
    AMOMINU_D_RL	= 143,
    AMOMINU_W	= 144,
    AMOMINU_W_AQ	= 145,
    AMOMINU_W_AQ_RL	= 146,
    AMOMINU_W_RL	= 147,
    AMOMIN_D	= 148,
    AMOMIN_D_AQ	= 149,
    AMOMIN_D_AQ_RL	= 150,
    AMOMIN_D_RL	= 151,
    AMOMIN_W	= 152,
    AMOMIN_W_AQ	= 153,
    AMOMIN_W_AQ_RL	= 154,
    AMOMIN_W_RL	= 155,
    AMOOR_D	= 156,
    AMOOR_D_AQ	= 157,
    AMOOR_D_AQ_RL	= 158,
    AMOOR_D_RL	= 159,
    AMOOR_W	= 160,
    AMOOR_W_AQ	= 161,
    AMOOR_W_AQ_RL	= 162,
    AMOOR_W_RL	= 163,
    AMOSWAP_D	= 164,
    AMOSWAP_D_AQ	= 165,
    AMOSWAP_D_AQ_RL	= 166,
    AMOSWAP_D_RL	= 167,
    AMOSWAP_W	= 168,
    AMOSWAP_W_AQ	= 169,
    AMOSWAP_W_AQ_RL	= 170,
    AMOSWAP_W_RL	= 171,
    AMOXOR_D	= 172,
    AMOXOR_D_AQ	= 173,
    AMOXOR_D_AQ_RL	= 174,
    AMOXOR_D_RL	= 175,
    AMOXOR_W	= 176,
    AMOXOR_W_AQ	= 177,
    AMOXOR_W_AQ_RL	= 178,
    AMOXOR_W_RL	= 179,
    AND	= 180,
    ANDI	= 181,
    AUIPC	= 182,
    BEQ	= 183,
    BGE	= 184,
    BGEU	= 185,
    BLT	= 186,
    BLTU	= 187,
    BNE	= 188,
    CSRRC	= 189,
    CSRRCI	= 190,
    CSRRS	= 191,
    CSRRSI	= 192,
    CSRRW	= 193,
    CSRRWI	= 194,
    DIV	= 195,
    DIVU	= 196,
    DIVUW	= 197,
    DIVW	= 198,
    EBREAK	= 199,
    ECALL	= 200,
    FADD_D	= 201,
    FADD_S	= 202,
    FCLASS_D	= 203,
    FCLASS_S	= 204,
    FCVT_D_L	= 205,
    FCVT_D_LU	= 206,
    FCVT_D_S	= 207,
    FCVT_D_W	= 208,
    FCVT_D_WU	= 209,
    FCVT_LU_D	= 210,
    FCVT_LU_S	= 211,
    FCVT_L_D	= 212,
    FCVT_L_S	= 213,
    FCVT_S_D	= 214,
    FCVT_S_L	= 215,
    FCVT_S_LU	= 216,
    FCVT_S_W	= 217,
    FCVT_S_WU	= 218,
    FCVT_WU_D	= 219,
    FCVT_WU_S	= 220,
    FCVT_W_D	= 221,
    FCVT_W_S	= 222,
    FDIV_D	= 223,
    FDIV_S	= 224,
    FENCE	= 225,
    FENCE_I	= 226,
    FEQ_D	= 227,
    FEQ_S	= 228,
    FLD	= 229,
    FLE_D	= 230,
    FLE_S	= 231,
    FLT_D	= 232,
    FLT_S	= 233,
    FLW	= 234,
    FMADD_D	= 235,
    FMADD_S	= 236,
    FMAX_D	= 237,
    FMAX_S	= 238,
    FMIN_D	= 239,
    FMIN_S	= 240,
    FMSUB_D	= 241,
    FMSUB_S	= 242,
    FMUL_D	= 243,
    FMUL_S	= 244,
    FMV_D_X	= 245,
    FMV_W_X	= 246,
    FMV_X_D	= 247,
    FMV_X_W	= 248,
    FNMADD_D	= 249,
    FNMADD_S	= 250,
    FNMSUB_D	= 251,
    FNMSUB_S	= 252,
    FSD	= 253,
    FSGNJN_D	= 254,
    FSGNJN_S	= 255,
    FSGNJX_D	= 256,
    FSGNJX_S	= 257,
    FSGNJ_D	= 258,
    FSGNJ_S	= 259,
    FSQRT_D	= 260,
    FSQRT_S	= 261,
    FSUB_D	= 262,
    FSUB_S	= 263,
    FSW	= 264,
    JAL	= 265,
    JALR	= 266,
    LB	= 267,
    LBU	= 268,
    LD	= 269,
    LEA_FI	= 270,
    LH	= 271,
    LHU	= 272,
    LR_D	= 273,
    LR_D_AQ	= 274,
    LR_D_AQ_RL	= 275,
    LR_D_RL	= 276,
    LR_W	= 277,
    LR_W_AQ	= 278,
    LR_W_AQ_RL	= 279,
    LR_W_RL	= 280,
    LUI	= 281,
    LW	= 282,
    LWU	= 283,
    LW_FI	= 284,
    MUL	= 285,
    MULH	= 286,
    MULHSU	= 287,
    MULHU	= 288,
    MULW	= 289,
    OR	= 290,
    ORI	= 291,
    PseudoBR	= 292,
    PseudoBRIND	= 293,
    PseudoCALL	= 294,
    PseudoRET	= 295,
    REM	= 296,
    REMU	= 297,
    REMUW	= 298,
    REMW	= 299,
    SB	= 300,
    SC_D	= 301,
    SC_D_AQ	= 302,
    SC_D_AQ_RL	= 303,
    SC_D_RL	= 304,
    SC_W	= 305,
    SC_W_AQ	= 306,
    SC_W_AQ_RL	= 307,
    SC_W_RL	= 308,
    SD	= 309,
    SH	= 310,
    SLL	= 311,
    SLLI	= 312,
    SLLIW	= 313,
    SLLW	= 314,
    SLT	= 315,
    SLTI	= 316,
    SLTIU	= 317,
    SLTU	= 318,
    SRA	= 319,
    SRAI	= 320,
    SRAIW	= 321,
    SRAW	= 322,
    SRL	= 323,
    SRLI	= 324,
    SRLIW	= 325,
    SRLW	= 326,
    SUB	= 327,
    SUBW	= 328,
    SW	= 329,
    SW_FI	= 330,
    Select	= 331,
    XOR	= 332,
    XORI	= 333,
    INSTRUCTION_LIST_END = 334
  };

namespace Sched {
  enum {
    NoInstrModel	= 0,
    SCHED_LIST_END = 1
  };
} // end Sched namespace
} // end RISCV namespace
} // end llvm namespace
#endif // GET_INSTRINFO_ENUM

#ifdef GET_INSTRINFO_MC_DESC
#undef GET_INSTRINFO_MC_DESC
namespace llvm {

static const MCPhysReg ImplicitList1[] = { RISCV::X2, 0 };
static const MCPhysReg ImplicitList2[] = { RISCV::X1, 0 };

static const MCOperandInfo OperandInfo2[] = { { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo3[] = { { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, };
static const MCOperandInfo OperandInfo4[] = { { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, };
static const MCOperandInfo OperandInfo5[] = { { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, ((0 << 16) | (1 << MCOI::TIED_TO)) }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, };
static const MCOperandInfo OperandInfo6[] = { { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, };
static const MCOperandInfo OperandInfo7[] = { { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo8[] = { { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, };
static const MCOperandInfo OperandInfo9[] = { { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, };
static const MCOperandInfo OperandInfo10[] = { { 0, 0|(1<<MCOI::LookupPtrRegClass), MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo11[] = { { 0, 0|(1<<MCOI::LookupPtrRegClass), MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, };
static const MCOperandInfo OperandInfo12[] = { { -1, 0, MCOI::OPERAND_GENERIC_0, 0 }, { -1, 0, MCOI::OPERAND_GENERIC_0, 0 }, { -1, 0, MCOI::OPERAND_GENERIC_0, 0 }, };
static const MCOperandInfo OperandInfo13[] = { { -1, 0, MCOI::OPERAND_GENERIC_0, 0 }, };
static const MCOperandInfo OperandInfo14[] = { { -1, 0, MCOI::OPERAND_GENERIC_0, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo15[] = { { -1, 0, MCOI::OPERAND_GENERIC_0, 0 }, { -1, 0, MCOI::OPERAND_GENERIC_1, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo16[] = { { -1, 0, MCOI::OPERAND_GENERIC_0, 0 }, { -1, 0, MCOI::OPERAND_GENERIC_0, 0 }, { -1, 0, MCOI::OPERAND_GENERIC_1, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo17[] = { { -1, 0, MCOI::OPERAND_GENERIC_0, 0 }, { -1, 0, MCOI::OPERAND_GENERIC_1, 0 }, };
static const MCOperandInfo OperandInfo18[] = { { -1, 0, MCOI::OPERAND_GENERIC_0, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_GENERIC_1, 0 }, { -1, 0, MCOI::OPERAND_GENERIC_1, 0 }, };
static const MCOperandInfo OperandInfo19[] = { { -1, 0, MCOI::OPERAND_GENERIC_0, 0 }, { -1, 0, MCOI::OPERAND_GENERIC_1, 0 }, { -1, 0, MCOI::OPERAND_GENERIC_0, 0 }, { -1, 0, MCOI::OPERAND_GENERIC_0, 0 }, };
static const MCOperandInfo OperandInfo20[] = { { -1, 0, MCOI::OPERAND_GENERIC_0, 0 }, { -1, 0, MCOI::OPERAND_GENERIC_1, 0 }, { -1, 0, MCOI::OPERAND_GENERIC_0, 0 }, { -1, 0, MCOI::OPERAND_GENERIC_0, 0 }, { -1, 0, MCOI::OPERAND_GENERIC_1, 0 }, };
static const MCOperandInfo OperandInfo21[] = { { -1, 0, MCOI::OPERAND_GENERIC_0, 0 }, { -1, 0, MCOI::OPERAND_GENERIC_0, 0 }, { -1, 0, MCOI::OPERAND_GENERIC_0, 0 }, { -1, 0, MCOI::OPERAND_GENERIC_0, 0 }, };
static const MCOperandInfo OperandInfo22[] = { { -1, 0, MCOI::OPERAND_GENERIC_0, 0 }, { -1, 0, MCOI::OPERAND_GENERIC_0, 0 }, };
static const MCOperandInfo OperandInfo23[] = { { -1, 0, MCOI::OPERAND_GENERIC_0, 0 }, { -1, 0, MCOI::OPERAND_GENERIC_0, 0 }, { -1, 0, MCOI::OPERAND_GENERIC_1, 0 }, };
static const MCOperandInfo OperandInfo24[] = { { -1, 0, MCOI::OPERAND_GENERIC_0, 0 }, { -1, 0, MCOI::OPERAND_GENERIC_0, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo25[] = { { -1, 0, MCOI::OPERAND_GENERIC_0, 0 }, { -1, 0, MCOI::OPERAND_GENERIC_0, 0 }, { -1, 0, MCOI::OPERAND_GENERIC_1, 0 }, { -1, 0, MCOI::OPERAND_GENERIC_2, 0 }, };
static const MCOperandInfo OperandInfo26[] = { { -1, 0, MCOI::OPERAND_GENERIC_0, 0 }, { -1, 0, MCOI::OPERAND_GENERIC_1, 0 }, { -1, 0, MCOI::OPERAND_GENERIC_2, 0 }, };
static const MCOperandInfo OperandInfo27[] = { { -1, 0, MCOI::OPERAND_GENERIC_0, 0 }, { -1, 0, MCOI::OPERAND_GENERIC_1, 0 }, { -1, 0, MCOI::OPERAND_GENERIC_1, 0 }, { -1, 0, MCOI::OPERAND_GENERIC_2, 0 }, };
static const MCOperandInfo OperandInfo28[] = { { RISCV::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { RISCV::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { RISCV::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo29[] = { { RISCV::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { RISCV::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo30[] = { { RISCV::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo31[] = { { RISCV::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { RISCV::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo32[] = { { RISCV::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo33[] = { { RISCV::FPR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { RISCV::FPR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { RISCV::FPR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo34[] = { { RISCV::FPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { RISCV::FPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { RISCV::FPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo35[] = { { RISCV::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { RISCV::FPR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo36[] = { { RISCV::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { RISCV::FPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo37[] = { { RISCV::FPR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { RISCV::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo38[] = { { RISCV::FPR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { RISCV::FPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo39[] = { { RISCV::FPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { RISCV::FPR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo40[] = { { RISCV::FPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { RISCV::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo41[] = { { RISCV::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { RISCV::FPR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { RISCV::FPR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo42[] = { { RISCV::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { RISCV::FPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { RISCV::FPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo43[] = { { RISCV::FPR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { RISCV::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo44[] = { { RISCV::FPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { RISCV::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo45[] = { { RISCV::FPR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { RISCV::FPR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { RISCV::FPR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { RISCV::FPR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo46[] = { { RISCV::FPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { RISCV::FPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { RISCV::FPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { RISCV::FPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo47[] = { { RISCV::FPR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { RISCV::FPR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo48[] = { { RISCV::FPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { RISCV::FPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo49[] = { { RISCV::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { RISCV::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo50[] = { { RISCV::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo51[] = { { RISCV::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { RISCV::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { RISCV::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { RISCV::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { RISCV::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };

extern const MCInstrDesc RISCVInsts[] = {
  { 0,	1,	1,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo2, -1 ,nullptr },  // Inst #0 = PHI
  { 1,	0,	0,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Variadic), 0x0ULL, nullptr, nullptr, nullptr, -1 ,nullptr },  // Inst #1 = INLINEASM
  { 2,	1,	0,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::NotDuplicable)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo3, -1 ,nullptr },  // Inst #2 = CFI_INSTRUCTION
  { 3,	1,	0,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::NotDuplicable)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo3, -1 ,nullptr },  // Inst #3 = EH_LABEL
  { 4,	1,	0,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::NotDuplicable)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo3, -1 ,nullptr },  // Inst #4 = GC_LABEL
  { 5,	0,	0,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Variadic), 0x0ULL, nullptr, nullptr, nullptr, -1 ,nullptr },  // Inst #5 = KILL
  { 6,	3,	1,	0,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo4, -1 ,nullptr },  // Inst #6 = EXTRACT_SUBREG
  { 7,	4,	1,	0,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo5, -1 ,nullptr },  // Inst #7 = INSERT_SUBREG
  { 8,	1,	1,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Rematerializable)|(1ULL<<MCID::CheapAsAMove), 0x0ULL, nullptr, nullptr, OperandInfo2, -1 ,nullptr },  // Inst #8 = IMPLICIT_DEF
  { 9,	4,	1,	0,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo6, -1 ,nullptr },  // Inst #9 = SUBREG_TO_REG
  { 10,	3,	1,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::CheapAsAMove), 0x0ULL, nullptr, nullptr, OperandInfo4, -1 ,nullptr },  // Inst #10 = COPY_TO_REGCLASS
  { 11,	0,	0,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Variadic), 0x0ULL, nullptr, nullptr, nullptr, -1 ,nullptr },  // Inst #11 = DBG_VALUE
  { 12,	2,	1,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::CheapAsAMove), 0x0ULL, nullptr, nullptr, OperandInfo7, -1 ,nullptr },  // Inst #12 = REG_SEQUENCE
  { 13,	2,	1,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::CheapAsAMove), 0x0ULL, nullptr, nullptr, OperandInfo7, -1 ,nullptr },  // Inst #13 = COPY
  { 14,	0,	0,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, nullptr, -1 ,nullptr },  // Inst #14 = BUNDLE
  { 15,	1,	0,	0,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo3, -1 ,nullptr },  // Inst #15 = LIFETIME_START
  { 16,	1,	0,	0,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo3, -1 ,nullptr },  // Inst #16 = LIFETIME_END
  { 17,	2,	0,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Call)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo8, -1 ,nullptr },  // Inst #17 = STACKMAP
  { 18,	1,	1,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo2, -1 ,nullptr },  // Inst #18 = FENTRY_CALL
  { 19,	6,	1,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Call)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo9, -1 ,nullptr },  // Inst #19 = PATCHPOINT
  { 20,	1,	1,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::Rematerializable), 0x0ULL, nullptr, nullptr, OperandInfo10, -1 ,nullptr },  // Inst #20 = LOAD_STACK_GUARD
  { 21,	0,	0,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Call)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, nullptr, -1 ,nullptr },  // Inst #21 = STATEPOINT
  { 22,	2,	0,	0,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo11, -1 ,nullptr },  // Inst #22 = LOCAL_ESCAPE
  { 23,	1,	1,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Branch)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo2, -1 ,nullptr },  // Inst #23 = FAULTING_OP
  { 24,	1,	1,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo2, -1 ,nullptr },  // Inst #24 = PATCHABLE_OP
  { 25,	0,	0,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL, nullptr, nullptr, nullptr, -1 ,nullptr },  // Inst #25 = PATCHABLE_FUNCTION_ENTER
  { 26,	1,	1,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Return)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo2, -1 ,nullptr },  // Inst #26 = PATCHABLE_RET
  { 27,	0,	0,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL, nullptr, nullptr, nullptr, -1 ,nullptr },  // Inst #27 = PATCHABLE_FUNCTION_EXIT
  { 28,	1,	1,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Return)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo2, -1 ,nullptr },  // Inst #28 = PATCHABLE_TAIL_CALL
  { 29,	2,	0,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Call)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo11, -1 ,nullptr },  // Inst #29 = PATCHABLE_EVENT_CALL
  { 30,	3,	1,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable), 0x0ULL, nullptr, nullptr, OperandInfo12, -1 ,nullptr },  // Inst #30 = G_ADD
  { 31,	3,	1,	0,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo12, -1 ,nullptr },  // Inst #31 = G_SUB
  { 32,	3,	1,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable), 0x0ULL, nullptr, nullptr, OperandInfo12, -1 ,nullptr },  // Inst #32 = G_MUL
  { 33,	3,	1,	0,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo12, -1 ,nullptr },  // Inst #33 = G_SDIV
  { 34,	3,	1,	0,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo12, -1 ,nullptr },  // Inst #34 = G_UDIV
  { 35,	3,	1,	0,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo12, -1 ,nullptr },  // Inst #35 = G_SREM
  { 36,	3,	1,	0,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo12, -1 ,nullptr },  // Inst #36 = G_UREM
  { 37,	3,	1,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable), 0x0ULL, nullptr, nullptr, OperandInfo12, -1 ,nullptr },  // Inst #37 = G_AND
  { 38,	3,	1,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable), 0x0ULL, nullptr, nullptr, OperandInfo12, -1 ,nullptr },  // Inst #38 = G_OR
  { 39,	3,	1,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable), 0x0ULL, nullptr, nullptr, OperandInfo12, -1 ,nullptr },  // Inst #39 = G_XOR
  { 40,	1,	1,	0,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #40 = G_IMPLICIT_DEF
  { 41,	2,	1,	0,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo14, -1 ,nullptr },  // Inst #41 = G_FRAME_INDEX
  { 42,	2,	1,	0,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo14, -1 ,nullptr },  // Inst #42 = G_GLOBAL_VALUE
  { 43,	3,	1,	0,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo15, -1 ,nullptr },  // Inst #43 = G_EXTRACT
  { 44,	0,	0,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Variadic), 0x0ULL, nullptr, nullptr, nullptr, -1 ,nullptr },  // Inst #44 = G_UNMERGE_VALUES
  { 45,	4,	1,	0,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo16, -1 ,nullptr },  // Inst #45 = G_INSERT
  { 46,	1,	1,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Variadic), 0x0ULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #46 = G_MERGE_VALUES
  { 47,	2,	1,	0,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo17, -1 ,nullptr },  // Inst #47 = G_PTRTOINT
  { 48,	2,	1,	0,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo17, -1 ,nullptr },  // Inst #48 = G_INTTOPTR
  { 49,	2,	1,	0,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo17, -1 ,nullptr },  // Inst #49 = G_BITCAST
  { 50,	2,	1,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad), 0x0ULL, nullptr, nullptr, OperandInfo17, -1 ,nullptr },  // Inst #50 = G_LOAD
  { 51,	2,	0,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayStore), 0x0ULL, nullptr, nullptr, OperandInfo17, -1 ,nullptr },  // Inst #51 = G_STORE
  { 52,	2,	0,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x0ULL, nullptr, nullptr, OperandInfo14, -1 ,nullptr },  // Inst #52 = G_BRCOND
  { 53,	1,	0,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x0ULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #53 = G_BRINDIRECT
  { 54,	1,	0,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Variadic), 0x0ULL, nullptr, nullptr, OperandInfo2, -1 ,nullptr },  // Inst #54 = G_INTRINSIC
  { 55,	1,	0,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo2, -1 ,nullptr },  // Inst #55 = G_INTRINSIC_W_SIDE_EFFECTS
  { 56,	2,	1,	0,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo17, -1 ,nullptr },  // Inst #56 = G_ANYEXT
  { 57,	2,	1,	0,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo17, -1 ,nullptr },  // Inst #57 = G_TRUNC
  { 58,	2,	1,	0,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo14, -1 ,nullptr },  // Inst #58 = G_CONSTANT
  { 59,	2,	1,	0,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo14, -1 ,nullptr },  // Inst #59 = G_FCONSTANT
  { 60,	1,	0,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayStore), 0x0ULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #60 = G_VASTART
  { 61,	3,	1,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL, nullptr, nullptr, OperandInfo15, -1 ,nullptr },  // Inst #61 = G_VAARG
  { 62,	2,	1,	0,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo17, -1 ,nullptr },  // Inst #62 = G_SEXT
  { 63,	2,	1,	0,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo17, -1 ,nullptr },  // Inst #63 = G_ZEXT
  { 64,	3,	1,	0,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo12, -1 ,nullptr },  // Inst #64 = G_SHL
  { 65,	3,	1,	0,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo12, -1 ,nullptr },  // Inst #65 = G_LSHR
  { 66,	3,	1,	0,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo12, -1 ,nullptr },  // Inst #66 = G_ASHR
  { 67,	4,	1,	0,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo18, -1 ,nullptr },  // Inst #67 = G_ICMP
  { 68,	4,	1,	0,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo18, -1 ,nullptr },  // Inst #68 = G_FCMP
  { 69,	4,	1,	0,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo19, -1 ,nullptr },  // Inst #69 = G_SELECT
  { 70,	5,	2,	0,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo20, -1 ,nullptr },  // Inst #70 = G_UADDE
  { 71,	5,	2,	0,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo20, -1 ,nullptr },  // Inst #71 = G_USUBE
  { 72,	4,	2,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable), 0x0ULL, nullptr, nullptr, OperandInfo19, -1 ,nullptr },  // Inst #72 = G_SADDO
  { 73,	4,	2,	0,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo19, -1 ,nullptr },  // Inst #73 = G_SSUBO
  { 74,	4,	2,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable), 0x0ULL, nullptr, nullptr, OperandInfo19, -1 ,nullptr },  // Inst #74 = G_UMULO
  { 75,	4,	2,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable), 0x0ULL, nullptr, nullptr, OperandInfo19, -1 ,nullptr },  // Inst #75 = G_SMULO
  { 76,	3,	1,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable), 0x0ULL, nullptr, nullptr, OperandInfo12, -1 ,nullptr },  // Inst #76 = G_UMULH
  { 77,	3,	1,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable), 0x0ULL, nullptr, nullptr, OperandInfo12, -1 ,nullptr },  // Inst #77 = G_SMULH
  { 78,	3,	1,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable), 0x0ULL, nullptr, nullptr, OperandInfo12, -1 ,nullptr },  // Inst #78 = G_FADD
  { 79,	3,	1,	0,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo12, -1 ,nullptr },  // Inst #79 = G_FSUB
  { 80,	3,	1,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable), 0x0ULL, nullptr, nullptr, OperandInfo12, -1 ,nullptr },  // Inst #80 = G_FMUL
  { 81,	4,	1,	0,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo21, -1 ,nullptr },  // Inst #81 = G_FMA
  { 82,	3,	1,	0,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo12, -1 ,nullptr },  // Inst #82 = G_FDIV
  { 83,	3,	1,	0,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo12, -1 ,nullptr },  // Inst #83 = G_FREM
  { 84,	3,	1,	0,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo12, -1 ,nullptr },  // Inst #84 = G_FPOW
  { 85,	2,	1,	0,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo22, -1 ,nullptr },  // Inst #85 = G_FEXP
  { 86,	2,	1,	0,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo22, -1 ,nullptr },  // Inst #86 = G_FEXP2
  { 87,	2,	1,	0,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo22, -1 ,nullptr },  // Inst #87 = G_FLOG
  { 88,	2,	1,	0,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo22, -1 ,nullptr },  // Inst #88 = G_FLOG2
  { 89,	2,	1,	0,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo22, -1 ,nullptr },  // Inst #89 = G_FNEG
  { 90,	2,	1,	0,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo17, -1 ,nullptr },  // Inst #90 = G_FPEXT
  { 91,	2,	1,	0,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo17, -1 ,nullptr },  // Inst #91 = G_FPTRUNC
  { 92,	2,	1,	0,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo17, -1 ,nullptr },  // Inst #92 = G_FPTOSI
  { 93,	2,	1,	0,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo17, -1 ,nullptr },  // Inst #93 = G_FPTOUI
  { 94,	2,	1,	0,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo17, -1 ,nullptr },  // Inst #94 = G_SITOFP
  { 95,	2,	1,	0,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo17, -1 ,nullptr },  // Inst #95 = G_UITOFP
  { 96,	3,	1,	0,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo23, -1 ,nullptr },  // Inst #96 = G_GEP
  { 97,	3,	1,	0,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo24, -1 ,nullptr },  // Inst #97 = G_PTR_MASK
  { 98,	1,	0,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Branch)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::Terminator), 0x0ULL, nullptr, nullptr, OperandInfo2, -1 ,nullptr },  // Inst #98 = G_BR
  { 99,	4,	1,	0,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo25, -1 ,nullptr },  // Inst #99 = G_INSERT_VECTOR_ELT
  { 100,	3,	1,	0,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo26, -1 ,nullptr },  // Inst #100 = G_EXTRACT_VECTOR_ELT
  { 101,	4,	1,	0,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo27, -1 ,nullptr },  // Inst #101 = G_SHUFFLE_VECTOR
  { 102,	3,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo28, -1 ,nullptr },  // Inst #102 = ADD
  { 103,	3,	1,	4,	0,	0, 0x3ULL, nullptr, nullptr, OperandInfo29, -1 ,nullptr },  // Inst #103 = ADDI
  { 104,	3,	1,	4,	0,	0, 0x3ULL, nullptr, nullptr, OperandInfo29, -1 ,nullptr },  // Inst #104 = ADDIW
  { 105,	3,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo28, -1 ,nullptr },  // Inst #105 = ADDW
  { 106,	2,	0,	4,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, ImplicitList1, ImplicitList1, OperandInfo8, -1 ,nullptr },  // Inst #106 = ADJCALLSTACKDOWN
  { 107,	2,	0,	4,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, ImplicitList1, ImplicitList1, OperandInfo8, -1 ,nullptr },  // Inst #107 = ADJCALLSTACKUP
  { 108,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo28, -1 ,nullptr },  // Inst #108 = AMOADD_D
  { 109,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo28, -1 ,nullptr },  // Inst #109 = AMOADD_D_AQ
  { 110,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo28, -1 ,nullptr },  // Inst #110 = AMOADD_D_AQ_RL
  { 111,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo28, -1 ,nullptr },  // Inst #111 = AMOADD_D_RL
  { 112,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo28, -1 ,nullptr },  // Inst #112 = AMOADD_W
  { 113,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo28, -1 ,nullptr },  // Inst #113 = AMOADD_W_AQ
  { 114,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo28, -1 ,nullptr },  // Inst #114 = AMOADD_W_AQ_RL
  { 115,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo28, -1 ,nullptr },  // Inst #115 = AMOADD_W_RL
  { 116,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo28, -1 ,nullptr },  // Inst #116 = AMOAND_D
  { 117,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo28, -1 ,nullptr },  // Inst #117 = AMOAND_D_AQ
  { 118,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo28, -1 ,nullptr },  // Inst #118 = AMOAND_D_AQ_RL
  { 119,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo28, -1 ,nullptr },  // Inst #119 = AMOAND_D_RL
  { 120,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo28, -1 ,nullptr },  // Inst #120 = AMOAND_W
  { 121,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo28, -1 ,nullptr },  // Inst #121 = AMOAND_W_AQ
  { 122,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo28, -1 ,nullptr },  // Inst #122 = AMOAND_W_AQ_RL
  { 123,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo28, -1 ,nullptr },  // Inst #123 = AMOAND_W_RL
  { 124,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo28, -1 ,nullptr },  // Inst #124 = AMOMAXU_D
  { 125,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo28, -1 ,nullptr },  // Inst #125 = AMOMAXU_D_AQ
  { 126,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo28, -1 ,nullptr },  // Inst #126 = AMOMAXU_D_AQ_RL
  { 127,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo28, -1 ,nullptr },  // Inst #127 = AMOMAXU_D_RL
  { 128,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo28, -1 ,nullptr },  // Inst #128 = AMOMAXU_W
  { 129,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo28, -1 ,nullptr },  // Inst #129 = AMOMAXU_W_AQ
  { 130,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo28, -1 ,nullptr },  // Inst #130 = AMOMAXU_W_AQ_RL
  { 131,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo28, -1 ,nullptr },  // Inst #131 = AMOMAXU_W_RL
  { 132,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo28, -1 ,nullptr },  // Inst #132 = AMOMAX_D
  { 133,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo28, -1 ,nullptr },  // Inst #133 = AMOMAX_D_AQ
  { 134,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo28, -1 ,nullptr },  // Inst #134 = AMOMAX_D_AQ_RL
  { 135,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo28, -1 ,nullptr },  // Inst #135 = AMOMAX_D_RL
  { 136,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo28, -1 ,nullptr },  // Inst #136 = AMOMAX_W
  { 137,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo28, -1 ,nullptr },  // Inst #137 = AMOMAX_W_AQ
  { 138,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo28, -1 ,nullptr },  // Inst #138 = AMOMAX_W_AQ_RL
  { 139,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo28, -1 ,nullptr },  // Inst #139 = AMOMAX_W_RL
  { 140,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo28, -1 ,nullptr },  // Inst #140 = AMOMINU_D
  { 141,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo28, -1 ,nullptr },  // Inst #141 = AMOMINU_D_AQ
  { 142,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo28, -1 ,nullptr },  // Inst #142 = AMOMINU_D_AQ_RL
  { 143,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo28, -1 ,nullptr },  // Inst #143 = AMOMINU_D_RL
  { 144,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo28, -1 ,nullptr },  // Inst #144 = AMOMINU_W
  { 145,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo28, -1 ,nullptr },  // Inst #145 = AMOMINU_W_AQ
  { 146,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo28, -1 ,nullptr },  // Inst #146 = AMOMINU_W_AQ_RL
  { 147,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo28, -1 ,nullptr },  // Inst #147 = AMOMINU_W_RL
  { 148,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo28, -1 ,nullptr },  // Inst #148 = AMOMIN_D
  { 149,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo28, -1 ,nullptr },  // Inst #149 = AMOMIN_D_AQ
  { 150,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo28, -1 ,nullptr },  // Inst #150 = AMOMIN_D_AQ_RL
  { 151,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo28, -1 ,nullptr },  // Inst #151 = AMOMIN_D_RL
  { 152,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo28, -1 ,nullptr },  // Inst #152 = AMOMIN_W
  { 153,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo28, -1 ,nullptr },  // Inst #153 = AMOMIN_W_AQ
  { 154,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo28, -1 ,nullptr },  // Inst #154 = AMOMIN_W_AQ_RL
  { 155,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo28, -1 ,nullptr },  // Inst #155 = AMOMIN_W_RL
  { 156,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo28, -1 ,nullptr },  // Inst #156 = AMOOR_D
  { 157,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo28, -1 ,nullptr },  // Inst #157 = AMOOR_D_AQ
  { 158,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo28, -1 ,nullptr },  // Inst #158 = AMOOR_D_AQ_RL
  { 159,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo28, -1 ,nullptr },  // Inst #159 = AMOOR_D_RL
  { 160,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo28, -1 ,nullptr },  // Inst #160 = AMOOR_W
  { 161,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo28, -1 ,nullptr },  // Inst #161 = AMOOR_W_AQ
  { 162,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo28, -1 ,nullptr },  // Inst #162 = AMOOR_W_AQ_RL
  { 163,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo28, -1 ,nullptr },  // Inst #163 = AMOOR_W_RL
  { 164,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo28, -1 ,nullptr },  // Inst #164 = AMOSWAP_D
  { 165,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo28, -1 ,nullptr },  // Inst #165 = AMOSWAP_D_AQ
  { 166,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo28, -1 ,nullptr },  // Inst #166 = AMOSWAP_D_AQ_RL
  { 167,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo28, -1 ,nullptr },  // Inst #167 = AMOSWAP_D_RL
  { 168,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo28, -1 ,nullptr },  // Inst #168 = AMOSWAP_W
  { 169,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo28, -1 ,nullptr },  // Inst #169 = AMOSWAP_W_AQ
  { 170,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo28, -1 ,nullptr },  // Inst #170 = AMOSWAP_W_AQ_RL
  { 171,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo28, -1 ,nullptr },  // Inst #171 = AMOSWAP_W_RL
  { 172,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo28, -1 ,nullptr },  // Inst #172 = AMOXOR_D
  { 173,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo28, -1 ,nullptr },  // Inst #173 = AMOXOR_D_AQ
  { 174,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo28, -1 ,nullptr },  // Inst #174 = AMOXOR_D_AQ_RL
  { 175,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo28, -1 ,nullptr },  // Inst #175 = AMOXOR_D_RL
  { 176,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo28, -1 ,nullptr },  // Inst #176 = AMOXOR_W
  { 177,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo28, -1 ,nullptr },  // Inst #177 = AMOXOR_W_AQ
  { 178,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo28, -1 ,nullptr },  // Inst #178 = AMOXOR_W_AQ_RL
  { 179,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo28, -1 ,nullptr },  // Inst #179 = AMOXOR_W_RL
  { 180,	3,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo28, -1 ,nullptr },  // Inst #180 = AND
  { 181,	3,	1,	4,	0,	0, 0x3ULL, nullptr, nullptr, OperandInfo29, -1 ,nullptr },  // Inst #181 = ANDI
  { 182,	2,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo30, -1 ,nullptr },  // Inst #182 = AUIPC
  { 183,	3,	0,	4,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x5ULL, nullptr, nullptr, OperandInfo29, -1 ,nullptr },  // Inst #183 = BEQ
  { 184,	3,	0,	4,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x5ULL, nullptr, nullptr, OperandInfo29, -1 ,nullptr },  // Inst #184 = BGE
  { 185,	3,	0,	4,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x5ULL, nullptr, nullptr, OperandInfo29, -1 ,nullptr },  // Inst #185 = BGEU
  { 186,	3,	0,	4,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x5ULL, nullptr, nullptr, OperandInfo29, -1 ,nullptr },  // Inst #186 = BLT
  { 187,	3,	0,	4,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x5ULL, nullptr, nullptr, OperandInfo29, -1 ,nullptr },  // Inst #187 = BLTU
  { 188,	3,	0,	4,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x5ULL, nullptr, nullptr, OperandInfo29, -1 ,nullptr },  // Inst #188 = BNE
  { 189,	3,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x3ULL, nullptr, nullptr, OperandInfo31, -1 ,nullptr },  // Inst #189 = CSRRC
  { 190,	3,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x3ULL, nullptr, nullptr, OperandInfo32, -1 ,nullptr },  // Inst #190 = CSRRCI
  { 191,	3,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x3ULL, nullptr, nullptr, OperandInfo31, -1 ,nullptr },  // Inst #191 = CSRRS
  { 192,	3,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x3ULL, nullptr, nullptr, OperandInfo32, -1 ,nullptr },  // Inst #192 = CSRRSI
  { 193,	3,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x3ULL, nullptr, nullptr, OperandInfo31, -1 ,nullptr },  // Inst #193 = CSRRW
  { 194,	3,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x3ULL, nullptr, nullptr, OperandInfo32, -1 ,nullptr },  // Inst #194 = CSRRWI
  { 195,	3,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo28, -1 ,nullptr },  // Inst #195 = DIV
  { 196,	3,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo28, -1 ,nullptr },  // Inst #196 = DIVU
  { 197,	3,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo28, -1 ,nullptr },  // Inst #197 = DIVUW
  { 198,	3,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo28, -1 ,nullptr },  // Inst #198 = DIVW
  { 199,	0,	0,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x3ULL, nullptr, nullptr, nullptr, -1 ,nullptr },  // Inst #199 = EBREAK
  { 200,	0,	0,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x3ULL, nullptr, nullptr, nullptr, -1 ,nullptr },  // Inst #200 = ECALL
  { 201,	3,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo33, -1 ,nullptr },  // Inst #201 = FADD_D
  { 202,	3,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo34, -1 ,nullptr },  // Inst #202 = FADD_S
  { 203,	2,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo35, -1 ,nullptr },  // Inst #203 = FCLASS_D
  { 204,	2,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo36, -1 ,nullptr },  // Inst #204 = FCLASS_S
  { 205,	2,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo37, -1 ,nullptr },  // Inst #205 = FCVT_D_L
  { 206,	2,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo37, -1 ,nullptr },  // Inst #206 = FCVT_D_LU
  { 207,	2,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo38, -1 ,nullptr },  // Inst #207 = FCVT_D_S
  { 208,	2,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo37, -1 ,nullptr },  // Inst #208 = FCVT_D_W
  { 209,	2,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo37, -1 ,nullptr },  // Inst #209 = FCVT_D_WU
  { 210,	2,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo35, -1 ,nullptr },  // Inst #210 = FCVT_LU_D
  { 211,	2,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo36, -1 ,nullptr },  // Inst #211 = FCVT_LU_S
  { 212,	2,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo35, -1 ,nullptr },  // Inst #212 = FCVT_L_D
  { 213,	2,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo36, -1 ,nullptr },  // Inst #213 = FCVT_L_S
  { 214,	2,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo39, -1 ,nullptr },  // Inst #214 = FCVT_S_D
  { 215,	2,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo40, -1 ,nullptr },  // Inst #215 = FCVT_S_L
  { 216,	2,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo40, -1 ,nullptr },  // Inst #216 = FCVT_S_LU
  { 217,	2,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo40, -1 ,nullptr },  // Inst #217 = FCVT_S_W
  { 218,	2,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo40, -1 ,nullptr },  // Inst #218 = FCVT_S_WU
  { 219,	2,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo35, -1 ,nullptr },  // Inst #219 = FCVT_WU_D
  { 220,	2,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo36, -1 ,nullptr },  // Inst #220 = FCVT_WU_S
  { 221,	2,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo35, -1 ,nullptr },  // Inst #221 = FCVT_W_D
  { 222,	2,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo36, -1 ,nullptr },  // Inst #222 = FCVT_W_S
  { 223,	3,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo33, -1 ,nullptr },  // Inst #223 = FDIV_D
  { 224,	3,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo34, -1 ,nullptr },  // Inst #224 = FDIV_S
  { 225,	2,	0,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x3ULL, nullptr, nullptr, OperandInfo7, -1 ,nullptr },  // Inst #225 = FENCE
  { 226,	0,	0,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x3ULL, nullptr, nullptr, nullptr, -1 ,nullptr },  // Inst #226 = FENCE_I
  { 227,	3,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo41, -1 ,nullptr },  // Inst #227 = FEQ_D
  { 228,	3,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo42, -1 ,nullptr },  // Inst #228 = FEQ_S
  { 229,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad), 0x3ULL, nullptr, nullptr, OperandInfo43, -1 ,nullptr },  // Inst #229 = FLD
  { 230,	3,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo41, -1 ,nullptr },  // Inst #230 = FLE_D
  { 231,	3,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo42, -1 ,nullptr },  // Inst #231 = FLE_S
  { 232,	3,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo41, -1 ,nullptr },  // Inst #232 = FLT_D
  { 233,	3,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo42, -1 ,nullptr },  // Inst #233 = FLT_S
  { 234,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad), 0x3ULL, nullptr, nullptr, OperandInfo44, -1 ,nullptr },  // Inst #234 = FLW
  { 235,	4,	1,	4,	0,	0, 0x2ULL, nullptr, nullptr, OperandInfo45, -1 ,nullptr },  // Inst #235 = FMADD_D
  { 236,	4,	1,	4,	0,	0, 0x2ULL, nullptr, nullptr, OperandInfo46, -1 ,nullptr },  // Inst #236 = FMADD_S
  { 237,	3,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo33, -1 ,nullptr },  // Inst #237 = FMAX_D
  { 238,	3,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo34, -1 ,nullptr },  // Inst #238 = FMAX_S
  { 239,	3,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo33, -1 ,nullptr },  // Inst #239 = FMIN_D
  { 240,	3,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo34, -1 ,nullptr },  // Inst #240 = FMIN_S
  { 241,	4,	1,	4,	0,	0, 0x2ULL, nullptr, nullptr, OperandInfo45, -1 ,nullptr },  // Inst #241 = FMSUB_D
  { 242,	4,	1,	4,	0,	0, 0x2ULL, nullptr, nullptr, OperandInfo46, -1 ,nullptr },  // Inst #242 = FMSUB_S
  { 243,	3,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo33, -1 ,nullptr },  // Inst #243 = FMUL_D
  { 244,	3,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo34, -1 ,nullptr },  // Inst #244 = FMUL_S
  { 245,	2,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo37, -1 ,nullptr },  // Inst #245 = FMV_D_X
  { 246,	2,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo40, -1 ,nullptr },  // Inst #246 = FMV_W_X
  { 247,	2,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo35, -1 ,nullptr },  // Inst #247 = FMV_X_D
  { 248,	2,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo36, -1 ,nullptr },  // Inst #248 = FMV_X_W
  { 249,	4,	1,	4,	0,	0, 0x2ULL, nullptr, nullptr, OperandInfo45, -1 ,nullptr },  // Inst #249 = FNMADD_D
  { 250,	4,	1,	4,	0,	0, 0x2ULL, nullptr, nullptr, OperandInfo46, -1 ,nullptr },  // Inst #250 = FNMADD_S
  { 251,	4,	1,	4,	0,	0, 0x2ULL, nullptr, nullptr, OperandInfo45, -1 ,nullptr },  // Inst #251 = FNMSUB_D
  { 252,	4,	1,	4,	0,	0, 0x2ULL, nullptr, nullptr, OperandInfo46, -1 ,nullptr },  // Inst #252 = FNMSUB_S
  { 253,	3,	0,	4,	0,	0|(1ULL<<MCID::MayLoad), 0x4ULL, nullptr, nullptr, OperandInfo43, -1 ,nullptr },  // Inst #253 = FSD
  { 254,	3,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo33, -1 ,nullptr },  // Inst #254 = FSGNJN_D
  { 255,	3,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo34, -1 ,nullptr },  // Inst #255 = FSGNJN_S
  { 256,	3,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo33, -1 ,nullptr },  // Inst #256 = FSGNJX_D
  { 257,	3,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo34, -1 ,nullptr },  // Inst #257 = FSGNJX_S
  { 258,	3,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo33, -1 ,nullptr },  // Inst #258 = FSGNJ_D
  { 259,	3,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo34, -1 ,nullptr },  // Inst #259 = FSGNJ_S
  { 260,	2,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo47, -1 ,nullptr },  // Inst #260 = FSQRT_D
  { 261,	2,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo48, -1 ,nullptr },  // Inst #261 = FSQRT_S
  { 262,	3,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo33, -1 ,nullptr },  // Inst #262 = FSUB_D
  { 263,	3,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo34, -1 ,nullptr },  // Inst #263 = FSUB_S
  { 264,	3,	0,	4,	0,	0|(1ULL<<MCID::MayLoad), 0x4ULL, nullptr, nullptr, OperandInfo44, -1 ,nullptr },  // Inst #264 = FSW
  { 265,	2,	1,	4,	0,	0|(1ULL<<MCID::Call), 0x7ULL, nullptr, nullptr, OperandInfo30, -1 ,nullptr },  // Inst #265 = JAL
  { 266,	3,	1,	4,	0,	0|(1ULL<<MCID::Call), 0x3ULL, nullptr, nullptr, OperandInfo29, -1 ,nullptr },  // Inst #266 = JALR
  { 267,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad), 0x3ULL, nullptr, nullptr, OperandInfo29, -1 ,nullptr },  // Inst #267 = LB
  { 268,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad), 0x3ULL, nullptr, nullptr, OperandInfo29, -1 ,nullptr },  // Inst #268 = LBU
  { 269,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad), 0x3ULL, nullptr, nullptr, OperandInfo29, -1 ,nullptr },  // Inst #269 = LD
  { 270,	3,	1,	4,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo32, -1 ,nullptr },  // Inst #270 = LEA_FI
  { 271,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad), 0x3ULL, nullptr, nullptr, OperandInfo29, -1 ,nullptr },  // Inst #271 = LH
  { 272,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad), 0x3ULL, nullptr, nullptr, OperandInfo29, -1 ,nullptr },  // Inst #272 = LHU
  { 273,	2,	1,	4,	0,	0|(1ULL<<MCID::MayLoad), 0x1ULL, nullptr, nullptr, OperandInfo49, -1 ,nullptr },  // Inst #273 = LR_D
  { 274,	2,	1,	4,	0,	0|(1ULL<<MCID::MayLoad), 0x1ULL, nullptr, nullptr, OperandInfo49, -1 ,nullptr },  // Inst #274 = LR_D_AQ
  { 275,	2,	1,	4,	0,	0|(1ULL<<MCID::MayLoad), 0x1ULL, nullptr, nullptr, OperandInfo49, -1 ,nullptr },  // Inst #275 = LR_D_AQ_RL
  { 276,	2,	1,	4,	0,	0|(1ULL<<MCID::MayLoad), 0x1ULL, nullptr, nullptr, OperandInfo49, -1 ,nullptr },  // Inst #276 = LR_D_RL
  { 277,	2,	1,	4,	0,	0|(1ULL<<MCID::MayLoad), 0x1ULL, nullptr, nullptr, OperandInfo49, -1 ,nullptr },  // Inst #277 = LR_W
  { 278,	2,	1,	4,	0,	0|(1ULL<<MCID::MayLoad), 0x1ULL, nullptr, nullptr, OperandInfo49, -1 ,nullptr },  // Inst #278 = LR_W_AQ
  { 279,	2,	1,	4,	0,	0|(1ULL<<MCID::MayLoad), 0x1ULL, nullptr, nullptr, OperandInfo49, -1 ,nullptr },  // Inst #279 = LR_W_AQ_RL
  { 280,	2,	1,	4,	0,	0|(1ULL<<MCID::MayLoad), 0x1ULL, nullptr, nullptr, OperandInfo49, -1 ,nullptr },  // Inst #280 = LR_W_RL
  { 281,	2,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo30, -1 ,nullptr },  // Inst #281 = LUI
  { 282,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad), 0x3ULL, nullptr, nullptr, OperandInfo29, -1 ,nullptr },  // Inst #282 = LW
  { 283,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad), 0x3ULL, nullptr, nullptr, OperandInfo29, -1 ,nullptr },  // Inst #283 = LWU
  { 284,	3,	1,	4,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad), 0x0ULL, nullptr, nullptr, OperandInfo32, -1 ,nullptr },  // Inst #284 = LW_FI
  { 285,	3,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo28, -1 ,nullptr },  // Inst #285 = MUL
  { 286,	3,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo28, -1 ,nullptr },  // Inst #286 = MULH
  { 287,	3,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo28, -1 ,nullptr },  // Inst #287 = MULHSU
  { 288,	3,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo28, -1 ,nullptr },  // Inst #288 = MULHU
  { 289,	3,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo28, -1 ,nullptr },  // Inst #289 = MULW
  { 290,	3,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo28, -1 ,nullptr },  // Inst #290 = OR
  { 291,	3,	1,	4,	0,	0, 0x3ULL, nullptr, nullptr, OperandInfo29, -1 ,nullptr },  // Inst #291 = ORI
  { 292,	1,	0,	4,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Branch)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::Terminator), 0x0ULL, nullptr, nullptr, OperandInfo2, -1 ,nullptr },  // Inst #292 = PseudoBR
  { 293,	2,	0,	4,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::Call)|(1ULL<<MCID::Terminator), 0x0ULL, nullptr, ImplicitList2, OperandInfo30, -1 ,nullptr },  // Inst #293 = PseudoBRIND
  { 294,	1,	0,	4,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Call), 0x0ULL, nullptr, ImplicitList2, OperandInfo50, -1 ,nullptr },  // Inst #294 = PseudoCALL
  { 295,	0,	0,	4,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Return)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::Terminator), 0x0ULL, nullptr, nullptr, nullptr, -1 ,nullptr },  // Inst #295 = PseudoRET
  { 296,	3,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo28, -1 ,nullptr },  // Inst #296 = REM
  { 297,	3,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo28, -1 ,nullptr },  // Inst #297 = REMU
  { 298,	3,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo28, -1 ,nullptr },  // Inst #298 = REMUW
  { 299,	3,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo28, -1 ,nullptr },  // Inst #299 = REMW
  { 300,	3,	0,	4,	0,	0|(1ULL<<MCID::MayStore), 0x4ULL, nullptr, nullptr, OperandInfo29, -1 ,nullptr },  // Inst #300 = SB
  { 301,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo28, -1 ,nullptr },  // Inst #301 = SC_D
  { 302,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo28, -1 ,nullptr },  // Inst #302 = SC_D_AQ
  { 303,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo28, -1 ,nullptr },  // Inst #303 = SC_D_AQ_RL
  { 304,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo28, -1 ,nullptr },  // Inst #304 = SC_D_RL
  { 305,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo28, -1 ,nullptr },  // Inst #305 = SC_W
  { 306,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo28, -1 ,nullptr },  // Inst #306 = SC_W_AQ
  { 307,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo28, -1 ,nullptr },  // Inst #307 = SC_W_AQ_RL
  { 308,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo28, -1 ,nullptr },  // Inst #308 = SC_W_RL
  { 309,	3,	0,	4,	0,	0|(1ULL<<MCID::MayStore), 0x4ULL, nullptr, nullptr, OperandInfo29, -1 ,nullptr },  // Inst #309 = SD
  { 310,	3,	0,	4,	0,	0|(1ULL<<MCID::MayStore), 0x4ULL, nullptr, nullptr, OperandInfo29, -1 ,nullptr },  // Inst #310 = SH
  { 311,	3,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo28, -1 ,nullptr },  // Inst #311 = SLL
  { 312,	3,	1,	4,	0,	0, 0x3ULL, nullptr, nullptr, OperandInfo29, -1 ,nullptr },  // Inst #312 = SLLI
  { 313,	3,	1,	4,	0,	0, 0x3ULL, nullptr, nullptr, OperandInfo29, -1 ,nullptr },  // Inst #313 = SLLIW
  { 314,	3,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo28, -1 ,nullptr },  // Inst #314 = SLLW
  { 315,	3,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo28, -1 ,nullptr },  // Inst #315 = SLT
  { 316,	3,	1,	4,	0,	0, 0x3ULL, nullptr, nullptr, OperandInfo29, -1 ,nullptr },  // Inst #316 = SLTI
  { 317,	3,	1,	4,	0,	0, 0x3ULL, nullptr, nullptr, OperandInfo29, -1 ,nullptr },  // Inst #317 = SLTIU
  { 318,	3,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo28, -1 ,nullptr },  // Inst #318 = SLTU
  { 319,	3,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo28, -1 ,nullptr },  // Inst #319 = SRA
  { 320,	3,	1,	4,	0,	0, 0x3ULL, nullptr, nullptr, OperandInfo29, -1 ,nullptr },  // Inst #320 = SRAI
  { 321,	3,	1,	4,	0,	0, 0x3ULL, nullptr, nullptr, OperandInfo29, -1 ,nullptr },  // Inst #321 = SRAIW
  { 322,	3,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo28, -1 ,nullptr },  // Inst #322 = SRAW
  { 323,	3,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo28, -1 ,nullptr },  // Inst #323 = SRL
  { 324,	3,	1,	4,	0,	0, 0x3ULL, nullptr, nullptr, OperandInfo29, -1 ,nullptr },  // Inst #324 = SRLI
  { 325,	3,	1,	4,	0,	0, 0x3ULL, nullptr, nullptr, OperandInfo29, -1 ,nullptr },  // Inst #325 = SRLIW
  { 326,	3,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo28, -1 ,nullptr },  // Inst #326 = SRLW
  { 327,	3,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo28, -1 ,nullptr },  // Inst #327 = SUB
  { 328,	3,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo28, -1 ,nullptr },  // Inst #328 = SUBW
  { 329,	3,	0,	4,	0,	0|(1ULL<<MCID::MayStore), 0x4ULL, nullptr, nullptr, OperandInfo29, -1 ,nullptr },  // Inst #329 = SW
  { 330,	3,	0,	4,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayStore), 0x0ULL, nullptr, nullptr, OperandInfo32, -1 ,nullptr },  // Inst #330 = SW_FI
  { 331,	6,	1,	4,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL, nullptr, nullptr, OperandInfo51, -1 ,nullptr },  // Inst #331 = Select
  { 332,	3,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo28, -1 ,nullptr },  // Inst #332 = XOR
  { 333,	3,	1,	4,	0,	0, 0x3ULL, nullptr, nullptr, OperandInfo29, -1 ,nullptr },  // Inst #333 = XORI
};

extern const char RISCVInstrNameData[] = {
  /* 0 */ 'G', '_', 'F', 'L', 'O', 'G', '2', 0,
  /* 8 */ 'G', '_', 'F', 'E', 'X', 'P', '2', 0,
  /* 16 */ 'G', '_', 'F', 'M', 'A', 0,
  /* 22 */ 'S', 'R', 'A', 0,
  /* 26 */ 'L', 'B', 0,
  /* 29 */ 'S', 'B', 0,
  /* 32 */ 'G', '_', 'F', 'S', 'U', 'B', 0,
  /* 39 */ 'G', '_', 'S', 'U', 'B', 0,
  /* 45 */ 'G', '_', 'I', 'N', 'T', 'R', 'I', 'N', 'S', 'I', 'C', 0,
  /* 57 */ 'G', '_', 'F', 'P', 'T', 'R', 'U', 'N', 'C', 0,
  /* 67 */ 'G', '_', 'T', 'R', 'U', 'N', 'C', 0,
  /* 75 */ 'A', 'U', 'I', 'P', 'C', 0,
  /* 81 */ 'C', 'S', 'R', 'R', 'C', 0,
  /* 87 */ 'G', '_', 'L', 'O', 'A', 'D', 0,
  /* 94 */ 'G', '_', 'F', 'A', 'D', 'D', 0,
  /* 101 */ 'G', '_', 'A', 'D', 'D', 0,
  /* 107 */ 'F', 'L', 'D', 0,
  /* 111 */ 'G', '_', 'A', 'N', 'D', 0,
  /* 117 */ 'L', 'I', 'F', 'E', 'T', 'I', 'M', 'E', '_', 'E', 'N', 'D', 0,
  /* 130 */ 'P', 's', 'e', 'u', 'd', 'o', 'B', 'R', 'I', 'N', 'D', 0,
  /* 142 */ 'G', '_', 'B', 'R', 'C', 'O', 'N', 'D', 0,
  /* 151 */ 'L', 'O', 'A', 'D', '_', 'S', 'T', 'A', 'C', 'K', '_', 'G', 'U', 'A', 'R', 'D', 0,
  /* 168 */ 'F', 'S', 'D', 0,
  /* 172 */ 'F', 'S', 'U', 'B', '_', 'D', 0,
  /* 179 */ 'F', 'M', 'S', 'U', 'B', '_', 'D', 0,
  /* 187 */ 'F', 'N', 'M', 'S', 'U', 'B', '_', 'D', 0,
  /* 196 */ 'S', 'C', '_', 'D', 0,
  /* 201 */ 'F', 'A', 'D', 'D', '_', 'D', 0,
  /* 208 */ 'F', 'M', 'A', 'D', 'D', '_', 'D', 0,
  /* 216 */ 'F', 'N', 'M', 'A', 'D', 'D', '_', 'D', 0,
  /* 225 */ 'A', 'M', 'O', 'A', 'D', 'D', '_', 'D', 0,
  /* 234 */ 'A', 'M', 'O', 'A', 'N', 'D', '_', 'D', 0,
  /* 243 */ 'F', 'L', 'E', '_', 'D', 0,
  /* 249 */ 'F', 'S', 'G', 'N', 'J', '_', 'D', 0,
  /* 257 */ 'F', 'M', 'U', 'L', '_', 'D', 0,
  /* 264 */ 'F', 'C', 'V', 'T', '_', 'L', '_', 'D', 0,
  /* 273 */ 'F', 'M', 'I', 'N', '_', 'D', 0,
  /* 280 */ 'A', 'M', 'O', 'M', 'I', 'N', '_', 'D', 0,
  /* 289 */ 'F', 'S', 'G', 'N', 'J', 'N', '_', 'D', 0,
  /* 298 */ 'A', 'M', 'O', 'S', 'W', 'A', 'P', '_', 'D', 0,
  /* 308 */ 'F', 'E', 'Q', '_', 'D', 0,
  /* 314 */ 'L', 'R', '_', 'D', 0,
  /* 319 */ 'A', 'M', 'O', 'O', 'R', '_', 'D', 0,
  /* 327 */ 'A', 'M', 'O', 'X', 'O', 'R', '_', 'D', 0,
  /* 336 */ 'F', 'C', 'L', 'A', 'S', 'S', '_', 'D', 0,
  /* 345 */ 'F', 'C', 'V', 'T', '_', 'S', '_', 'D', 0,
  /* 354 */ 'F', 'L', 'T', '_', 'D', 0,
  /* 360 */ 'F', 'S', 'Q', 'R', 'T', '_', 'D', 0,
  /* 368 */ 'F', 'C', 'V', 'T', '_', 'L', 'U', '_', 'D', 0,
  /* 378 */ 'A', 'M', 'O', 'M', 'I', 'N', 'U', '_', 'D', 0,
  /* 388 */ 'F', 'C', 'V', 'T', '_', 'W', 'U', '_', 'D', 0,
  /* 398 */ 'A', 'M', 'O', 'M', 'A', 'X', 'U', '_', 'D', 0,
  /* 408 */ 'F', 'D', 'I', 'V', '_', 'D', 0,
  /* 415 */ 'F', 'C', 'V', 'T', '_', 'W', '_', 'D', 0,
  /* 424 */ 'F', 'M', 'A', 'X', '_', 'D', 0,
  /* 431 */ 'A', 'M', 'O', 'M', 'A', 'X', '_', 'D', 0,
  /* 440 */ 'F', 'S', 'G', 'N', 'J', 'X', '_', 'D', 0,
  /* 449 */ 'F', 'M', 'V', '_', 'X', '_', 'D', 0,
  /* 457 */ 'G', '_', 'U', 'S', 'U', 'B', 'E', 0,
  /* 465 */ 'F', 'E', 'N', 'C', 'E', 0,
  /* 471 */ 'R', 'E', 'G', '_', 'S', 'E', 'Q', 'U', 'E', 'N', 'C', 'E', 0,
  /* 484 */ 'G', '_', 'U', 'A', 'D', 'D', 'E', 0,
  /* 492 */ 'B', 'G', 'E', 0,
  /* 496 */ 'B', 'U', 'N', 'D', 'L', 'E', 0,
  /* 503 */ 'B', 'N', 'E', 0,
  /* 507 */ 'L', 'O', 'C', 'A', 'L', '_', 'E', 'S', 'C', 'A', 'P', 'E', 0,
  /* 520 */ 'G', '_', 'S', 'T', 'O', 'R', 'E', 0,
  /* 528 */ 'D', 'B', 'G', '_', 'V', 'A', 'L', 'U', 'E', 0,
  /* 538 */ 'G', '_', 'G', 'L', 'O', 'B', 'A', 'L', '_', 'V', 'A', 'L', 'U', 'E', 0,
  /* 553 */ 'G', '_', 'I', 'M', 'P', 'L', 'I', 'C', 'I', 'T', '_', 'D', 'E', 'F', 0,
  /* 568 */ 'G', '_', 'F', 'N', 'E', 'G', 0,
  /* 575 */ 'E', 'X', 'T', 'R', 'A', 'C', 'T', '_', 'S', 'U', 'B', 'R', 'E', 'G', 0,
  /* 590 */ 'I', 'N', 'S', 'E', 'R', 'T', '_', 'S', 'U', 'B', 'R', 'E', 'G', 0,
  /* 604 */ 'S', 'U', 'B', 'R', 'E', 'G', '_', 'T', 'O', '_', 'R', 'E', 'G', 0,
  /* 618 */ 'G', '_', 'F', 'L', 'O', 'G', 0,
  /* 625 */ 'G', '_', 'V', 'A', 'A', 'R', 'G', 0,
  /* 633 */ 'G', '_', 'S', 'M', 'U', 'L', 'H', 0,
  /* 641 */ 'G', '_', 'U', 'M', 'U', 'L', 'H', 0,
  /* 649 */ 'S', 'H', 0,
  /* 652 */ 'S', 'R', 'A', 'I', 0,
  /* 657 */ 'C', 'S', 'R', 'R', 'C', 'I', 0,
  /* 664 */ 'A', 'D', 'D', 'I', 0,
  /* 669 */ 'A', 'N', 'D', 'I', 0,
  /* 674 */ 'L', 'E', 'A', '_', 'F', 'I', 0,
  /* 681 */ 'L', 'W', '_', 'F', 'I', 0,
  /* 687 */ 'S', 'W', '_', 'F', 'I', 0,
  /* 693 */ 'P', 'H', 'I', 0,
  /* 697 */ 'S', 'L', 'L', 'I', 0,
  /* 702 */ 'S', 'R', 'L', 'I', 0,
  /* 707 */ 'X', 'O', 'R', 'I', 0,
  /* 712 */ 'G', '_', 'F', 'P', 'T', 'O', 'S', 'I', 0,
  /* 721 */ 'C', 'S', 'R', 'R', 'S', 'I', 0,
  /* 728 */ 'S', 'L', 'T', 'I', 0,
  /* 733 */ 'L', 'U', 'I', 0,
  /* 737 */ 'G', '_', 'F', 'P', 'T', 'O', 'U', 'I', 0,
  /* 746 */ 'C', 'S', 'R', 'R', 'W', 'I', 0,
  /* 753 */ 'F', 'E', 'N', 'C', 'E', '_', 'I', 0,
  /* 761 */ 'E', 'B', 'R', 'E', 'A', 'K', 0,
  /* 768 */ 'G', '_', 'P', 'T', 'R', '_', 'M', 'A', 'S', 'K', 0,
  /* 779 */ 'J', 'A', 'L', 0,
  /* 783 */ 'G', 'C', '_', 'L', 'A', 'B', 'E', 'L', 0,
  /* 792 */ 'E', 'H', '_', 'L', 'A', 'B', 'E', 'L', 0,
  /* 801 */ 'G', '_', 'S', 'H', 'L', 0,
  /* 807 */ 'E', 'C', 'A', 'L', 'L', 0,
  /* 813 */ 'P', 'A', 'T', 'C', 'H', 'A', 'B', 'L', 'E', '_', 'T', 'A', 'I', 'L', '_', 'C', 'A', 'L', 'L', 0,
  /* 833 */ 'P', 'A', 'T', 'C', 'H', 'A', 'B', 'L', 'E', '_', 'E', 'V', 'E', 'N', 'T', '_', 'C', 'A', 'L', 'L', 0,
  /* 854 */ 'F', 'E', 'N', 'T', 'R', 'Y', '_', 'C', 'A', 'L', 'L', 0,
  /* 866 */ 'P', 's', 'e', 'u', 'd', 'o', 'C', 'A', 'L', 'L', 0,
  /* 877 */ 'K', 'I', 'L', 'L', 0,
  /* 882 */ 'S', 'L', 'L', 0,
  /* 886 */ 'S', 'R', 'L', 0,
  /* 890 */ 'S', 'C', '_', 'D', '_', 'R', 'L', 0,
  /* 898 */ 'A', 'M', 'O', 'A', 'D', 'D', '_', 'D', '_', 'R', 'L', 0,
  /* 910 */ 'A', 'M', 'O', 'A', 'N', 'D', '_', 'D', '_', 'R', 'L', 0,
  /* 922 */ 'A', 'M', 'O', 'M', 'I', 'N', '_', 'D', '_', 'R', 'L', 0,
  /* 934 */ 'A', 'M', 'O', 'S', 'W', 'A', 'P', '_', 'D', '_', 'R', 'L', 0,
  /* 947 */ 'L', 'R', '_', 'D', '_', 'R', 'L', 0,
  /* 955 */ 'A', 'M', 'O', 'O', 'R', '_', 'D', '_', 'R', 'L', 0,
  /* 966 */ 'A', 'M', 'O', 'X', 'O', 'R', '_', 'D', '_', 'R', 'L', 0,
  /* 978 */ 'A', 'M', 'O', 'M', 'I', 'N', 'U', '_', 'D', '_', 'R', 'L', 0,
  /* 991 */ 'A', 'M', 'O', 'M', 'A', 'X', 'U', '_', 'D', '_', 'R', 'L', 0,
  /* 1004 */ 'A', 'M', 'O', 'M', 'A', 'X', '_', 'D', '_', 'R', 'L', 0,
  /* 1016 */ 'S', 'C', '_', 'D', '_', 'A', 'Q', '_', 'R', 'L', 0,
  /* 1027 */ 'A', 'M', 'O', 'A', 'D', 'D', '_', 'D', '_', 'A', 'Q', '_', 'R', 'L', 0,
  /* 1042 */ 'A', 'M', 'O', 'A', 'N', 'D', '_', 'D', '_', 'A', 'Q', '_', 'R', 'L', 0,
  /* 1057 */ 'A', 'M', 'O', 'M', 'I', 'N', '_', 'D', '_', 'A', 'Q', '_', 'R', 'L', 0,
  /* 1072 */ 'A', 'M', 'O', 'S', 'W', 'A', 'P', '_', 'D', '_', 'A', 'Q', '_', 'R', 'L', 0,
  /* 1088 */ 'L', 'R', '_', 'D', '_', 'A', 'Q', '_', 'R', 'L', 0,
  /* 1099 */ 'A', 'M', 'O', 'O', 'R', '_', 'D', '_', 'A', 'Q', '_', 'R', 'L', 0,
  /* 1113 */ 'A', 'M', 'O', 'X', 'O', 'R', '_', 'D', '_', 'A', 'Q', '_', 'R', 'L', 0,
  /* 1128 */ 'A', 'M', 'O', 'M', 'I', 'N', 'U', '_', 'D', '_', 'A', 'Q', '_', 'R', 'L', 0,
  /* 1144 */ 'A', 'M', 'O', 'M', 'A', 'X', 'U', '_', 'D', '_', 'A', 'Q', '_', 'R', 'L', 0,
  /* 1160 */ 'A', 'M', 'O', 'M', 'A', 'X', '_', 'D', '_', 'A', 'Q', '_', 'R', 'L', 0,
  /* 1175 */ 'S', 'C', '_', 'W', '_', 'A', 'Q', '_', 'R', 'L', 0,
  /* 1186 */ 'A', 'M', 'O', 'A', 'D', 'D', '_', 'W', '_', 'A', 'Q', '_', 'R', 'L', 0,
  /* 1201 */ 'A', 'M', 'O', 'A', 'N', 'D', '_', 'W', '_', 'A', 'Q', '_', 'R', 'L', 0,
  /* 1216 */ 'A', 'M', 'O', 'M', 'I', 'N', '_', 'W', '_', 'A', 'Q', '_', 'R', 'L', 0,
  /* 1231 */ 'A', 'M', 'O', 'S', 'W', 'A', 'P', '_', 'W', '_', 'A', 'Q', '_', 'R', 'L', 0,
  /* 1247 */ 'L', 'R', '_', 'W', '_', 'A', 'Q', '_', 'R', 'L', 0,
  /* 1258 */ 'A', 'M', 'O', 'O', 'R', '_', 'W', '_', 'A', 'Q', '_', 'R', 'L', 0,
  /* 1272 */ 'A', 'M', 'O', 'X', 'O', 'R', '_', 'W', '_', 'A', 'Q', '_', 'R', 'L', 0,
  /* 1287 */ 'A', 'M', 'O', 'M', 'I', 'N', 'U', '_', 'W', '_', 'A', 'Q', '_', 'R', 'L', 0,
  /* 1303 */ 'A', 'M', 'O', 'M', 'A', 'X', 'U', '_', 'W', '_', 'A', 'Q', '_', 'R', 'L', 0,
  /* 1319 */ 'A', 'M', 'O', 'M', 'A', 'X', '_', 'W', '_', 'A', 'Q', '_', 'R', 'L', 0,
  /* 1334 */ 'S', 'C', '_', 'W', '_', 'R', 'L', 0,
  /* 1342 */ 'A', 'M', 'O', 'A', 'D', 'D', '_', 'W', '_', 'R', 'L', 0,
  /* 1354 */ 'A', 'M', 'O', 'A', 'N', 'D', '_', 'W', '_', 'R', 'L', 0,
  /* 1366 */ 'A', 'M', 'O', 'M', 'I', 'N', '_', 'W', '_', 'R', 'L', 0,
  /* 1378 */ 'A', 'M', 'O', 'S', 'W', 'A', 'P', '_', 'W', '_', 'R', 'L', 0,
  /* 1391 */ 'L', 'R', '_', 'W', '_', 'R', 'L', 0,
  /* 1399 */ 'A', 'M', 'O', 'O', 'R', '_', 'W', '_', 'R', 'L', 0,
  /* 1410 */ 'A', 'M', 'O', 'X', 'O', 'R', '_', 'W', '_', 'R', 'L', 0,
  /* 1422 */ 'A', 'M', 'O', 'M', 'I', 'N', 'U', '_', 'W', '_', 'R', 'L', 0,
  /* 1435 */ 'A', 'M', 'O', 'M', 'A', 'X', 'U', '_', 'W', '_', 'R', 'L', 0,
  /* 1448 */ 'A', 'M', 'O', 'M', 'A', 'X', '_', 'W', '_', 'R', 'L', 0,
  /* 1460 */ 'G', '_', 'F', 'M', 'U', 'L', 0,
  /* 1467 */ 'G', '_', 'M', 'U', 'L', 0,
  /* 1473 */ 'F', 'C', 'V', 'T', '_', 'D', '_', 'L', 0,
  /* 1482 */ 'F', 'C', 'V', 'T', '_', 'S', '_', 'L', 0,
  /* 1491 */ 'G', '_', 'F', 'R', 'E', 'M', 0,
  /* 1498 */ 'G', '_', 'S', 'R', 'E', 'M', 0,
  /* 1505 */ 'G', '_', 'U', 'R', 'E', 'M', 0,
  /* 1512 */ 'I', 'N', 'L', 'I', 'N', 'E', 'A', 'S', 'M', 0,
  /* 1522 */ 'C', 'F', 'I', '_', 'I', 'N', 'S', 'T', 'R', 'U', 'C', 'T', 'I', 'O', 'N', 0,
  /* 1538 */ 'A', 'D', 'J', 'C', 'A', 'L', 'L', 'S', 'T', 'A', 'C', 'K', 'D', 'O', 'W', 'N', 0,
  /* 1555 */ 'G', '_', 'S', 'S', 'U', 'B', 'O', 0,
  /* 1563 */ 'G', '_', 'S', 'A', 'D', 'D', 'O', 0,
  /* 1571 */ 'G', '_', 'S', 'M', 'U', 'L', 'O', 0,
  /* 1579 */ 'G', '_', 'U', 'M', 'U', 'L', 'O', 0,
  /* 1587 */ 'S', 'T', 'A', 'C', 'K', 'M', 'A', 'P', 0,
  /* 1596 */ 'G', '_', 'G', 'E', 'P', 0,
  /* 1602 */ 'G', '_', 'S', 'I', 'T', 'O', 'F', 'P', 0,
  /* 1611 */ 'G', '_', 'U', 'I', 'T', 'O', 'F', 'P', 0,
  /* 1620 */ 'G', '_', 'F', 'C', 'M', 'P', 0,
  /* 1627 */ 'G', '_', 'I', 'C', 'M', 'P', 0,
  /* 1634 */ 'P', 'A', 'T', 'C', 'H', 'A', 'B', 'L', 'E', '_', 'O', 'P', 0,
  /* 1647 */ 'F', 'A', 'U', 'L', 'T', 'I', 'N', 'G', '_', 'O', 'P', 0,
  /* 1659 */ 'A', 'D', 'J', 'C', 'A', 'L', 'L', 'S', 'T', 'A', 'C', 'K', 'U', 'P', 0,
  /* 1674 */ 'G', '_', 'F', 'E', 'X', 'P', 0,
  /* 1681 */ 'S', 'C', '_', 'D', '_', 'A', 'Q', 0,
  /* 1689 */ 'A', 'M', 'O', 'A', 'D', 'D', '_', 'D', '_', 'A', 'Q', 0,
  /* 1701 */ 'A', 'M', 'O', 'A', 'N', 'D', '_', 'D', '_', 'A', 'Q', 0,
  /* 1713 */ 'A', 'M', 'O', 'M', 'I', 'N', '_', 'D', '_', 'A', 'Q', 0,
  /* 1725 */ 'A', 'M', 'O', 'S', 'W', 'A', 'P', '_', 'D', '_', 'A', 'Q', 0,
  /* 1738 */ 'L', 'R', '_', 'D', '_', 'A', 'Q', 0,
  /* 1746 */ 'A', 'M', 'O', 'O', 'R', '_', 'D', '_', 'A', 'Q', 0,
  /* 1757 */ 'A', 'M', 'O', 'X', 'O', 'R', '_', 'D', '_', 'A', 'Q', 0,
  /* 1769 */ 'A', 'M', 'O', 'M', 'I', 'N', 'U', '_', 'D', '_', 'A', 'Q', 0,
  /* 1782 */ 'A', 'M', 'O', 'M', 'A', 'X', 'U', '_', 'D', '_', 'A', 'Q', 0,
  /* 1795 */ 'A', 'M', 'O', 'M', 'A', 'X', '_', 'D', '_', 'A', 'Q', 0,
  /* 1807 */ 'S', 'C', '_', 'W', '_', 'A', 'Q', 0,
  /* 1815 */ 'A', 'M', 'O', 'A', 'D', 'D', '_', 'W', '_', 'A', 'Q', 0,
  /* 1827 */ 'A', 'M', 'O', 'A', 'N', 'D', '_', 'W', '_', 'A', 'Q', 0,
  /* 1839 */ 'A', 'M', 'O', 'M', 'I', 'N', '_', 'W', '_', 'A', 'Q', 0,
  /* 1851 */ 'A', 'M', 'O', 'S', 'W', 'A', 'P', '_', 'W', '_', 'A', 'Q', 0,
  /* 1864 */ 'L', 'R', '_', 'W', '_', 'A', 'Q', 0,
  /* 1872 */ 'A', 'M', 'O', 'O', 'R', '_', 'W', '_', 'A', 'Q', 0,
  /* 1883 */ 'A', 'M', 'O', 'X', 'O', 'R', '_', 'W', '_', 'A', 'Q', 0,
  /* 1895 */ 'A', 'M', 'O', 'M', 'I', 'N', 'U', '_', 'W', '_', 'A', 'Q', 0,
  /* 1908 */ 'A', 'M', 'O', 'M', 'A', 'X', 'U', '_', 'W', '_', 'A', 'Q', 0,
  /* 1921 */ 'A', 'M', 'O', 'M', 'A', 'X', '_', 'W', '_', 'A', 'Q', 0,
  /* 1933 */ 'B', 'E', 'Q', 0,
  /* 1937 */ 'G', '_', 'B', 'R', 0,
  /* 1942 */ 'P', 's', 'e', 'u', 'd', 'o', 'B', 'R', 0,
  /* 1951 */ 'P', 'A', 'T', 'C', 'H', 'A', 'B', 'L', 'E', '_', 'F', 'U', 'N', 'C', 'T', 'I', 'O', 'N', '_', 'E', 'N', 'T', 'E', 'R', 0,
  /* 1976 */ 'G', '_', 'A', 'S', 'H', 'R', 0,
  /* 1983 */ 'G', '_', 'L', 'S', 'H', 'R', 0,
  /* 1990 */ 'J', 'A', 'L', 'R', 0,
  /* 1995 */ 'G', '_', 'S', 'H', 'U', 'F', 'F', 'L', 'E', '_', 'V', 'E', 'C', 'T', 'O', 'R', 0,
  /* 2012 */ 'G', '_', 'X', 'O', 'R', 0,
  /* 2018 */ 'G', '_', 'O', 'R', 0,
  /* 2023 */ 'G', '_', 'I', 'N', 'T', 'T', 'O', 'P', 'T', 'R', 0,
  /* 2034 */ 'G', '_', 'U', 'N', 'M', 'E', 'R', 'G', 'E', '_', 'V', 'A', 'L', 'U', 'E', 'S', 0,
  /* 2051 */ 'G', '_', 'M', 'E', 'R', 'G', 'E', '_', 'V', 'A', 'L', 'U', 'E', 'S', 0,
  /* 2066 */ 'C', 'S', 'R', 'R', 'S', 0,
  /* 2072 */ 'C', 'O', 'P', 'Y', '_', 'T', 'O', '_', 'R', 'E', 'G', 'C', 'L', 'A', 'S', 'S', 0,
  /* 2089 */ 'G', '_', 'I', 'N', 'T', 'R', 'I', 'N', 'S', 'I', 'C', '_', 'W', '_', 'S', 'I', 'D', 'E', '_', 'E', 'F', 'F', 'E', 'C', 'T', 'S', 0,
  /* 2116 */ 'F', 'S', 'U', 'B', '_', 'S', 0,
  /* 2123 */ 'F', 'M', 'S', 'U', 'B', '_', 'S', 0,
  /* 2131 */ 'F', 'N', 'M', 'S', 'U', 'B', '_', 'S', 0,
  /* 2140 */ 'F', 'A', 'D', 'D', '_', 'S', 0,
  /* 2147 */ 'F', 'M', 'A', 'D', 'D', '_', 'S', 0,
  /* 2155 */ 'F', 'N', 'M', 'A', 'D', 'D', '_', 'S', 0,
  /* 2164 */ 'F', 'C', 'V', 'T', '_', 'D', '_', 'S', 0,
  /* 2173 */ 'F', 'L', 'E', '_', 'S', 0,
  /* 2179 */ 'F', 'S', 'G', 'N', 'J', '_', 'S', 0,
  /* 2187 */ 'F', 'M', 'U', 'L', '_', 'S', 0,
  /* 2194 */ 'F', 'C', 'V', 'T', '_', 'L', '_', 'S', 0,
  /* 2203 */ 'F', 'M', 'I', 'N', '_', 'S', 0,
  /* 2210 */ 'F', 'S', 'G', 'N', 'J', 'N', '_', 'S', 0,
  /* 2219 */ 'F', 'E', 'Q', '_', 'S', 0,
  /* 2225 */ 'F', 'C', 'L', 'A', 'S', 'S', '_', 'S', 0,
  /* 2234 */ 'F', 'L', 'T', '_', 'S', 0,
  /* 2240 */ 'F', 'S', 'Q', 'R', 'T', '_', 'S', 0,
  /* 2248 */ 'F', 'C', 'V', 'T', '_', 'L', 'U', '_', 'S', 0,
  /* 2258 */ 'F', 'C', 'V', 'T', '_', 'W', 'U', '_', 'S', 0,
  /* 2268 */ 'F', 'D', 'I', 'V', '_', 'S', 0,
  /* 2275 */ 'F', 'C', 'V', 'T', '_', 'W', '_', 'S', 0,
  /* 2284 */ 'F', 'M', 'A', 'X', '_', 'S', 0,
  /* 2291 */ 'F', 'S', 'G', 'N', 'J', 'X', '_', 'S', 0,
  /* 2300 */ 'G', '_', 'E', 'X', 'T', 'R', 'A', 'C', 'T', 0,
  /* 2310 */ 'G', '_', 'S', 'E', 'L', 'E', 'C', 'T', 0,
  /* 2319 */ 'G', '_', 'B', 'R', 'I', 'N', 'D', 'I', 'R', 'E', 'C', 'T', 0,
  /* 2332 */ 'P', 'A', 'T', 'C', 'H', 'A', 'B', 'L', 'E', '_', 'R', 'E', 'T', 0,
  /* 2346 */ 'P', 's', 'e', 'u', 'd', 'o', 'R', 'E', 'T', 0,
  /* 2356 */ 'P', 'A', 'T', 'C', 'H', 'A', 'B', 'L', 'E', '_', 'F', 'U', 'N', 'C', 'T', 'I', 'O', 'N', '_', 'E', 'X', 'I', 'T', 0,
  /* 2380 */ 'B', 'L', 'T', 0,
  /* 2384 */ 'G', '_', 'E', 'X', 'T', 'R', 'A', 'C', 'T', '_', 'V', 'E', 'C', 'T', 'O', 'R', '_', 'E', 'L', 'T', 0,
  /* 2405 */ 'G', '_', 'I', 'N', 'S', 'E', 'R', 'T', '_', 'V', 'E', 'C', 'T', 'O', 'R', '_', 'E', 'L', 'T', 0,
  /* 2425 */ 'S', 'L', 'T', 0,
  /* 2429 */ 'G', '_', 'F', 'C', 'O', 'N', 'S', 'T', 'A', 'N', 'T', 0,
  /* 2441 */ 'G', '_', 'C', 'O', 'N', 'S', 'T', 'A', 'N', 'T', 0,
  /* 2452 */ 'S', 'T', 'A', 'T', 'E', 'P', 'O', 'I', 'N', 'T', 0,
  /* 2463 */ 'P', 'A', 'T', 'C', 'H', 'P', 'O', 'I', 'N', 'T', 0,
  /* 2474 */ 'G', '_', 'P', 'T', 'R', 'T', 'O', 'I', 'N', 'T', 0,
  /* 2485 */ 'G', '_', 'V', 'A', 'S', 'T', 'A', 'R', 'T', 0,
  /* 2495 */ 'L', 'I', 'F', 'E', 'T', 'I', 'M', 'E', '_', 'S', 'T', 'A', 'R', 'T', 0,
  /* 2510 */ 'G', '_', 'I', 'N', 'S', 'E', 'R', 'T', 0,
  /* 2519 */ 'G', '_', 'B', 'I', 'T', 'C', 'A', 'S', 'T', 0,
  /* 2529 */ 'G', '_', 'F', 'P', 'E', 'X', 'T', 0,
  /* 2537 */ 'G', '_', 'S', 'E', 'X', 'T', 0,
  /* 2544 */ 'G', '_', 'A', 'N', 'Y', 'E', 'X', 'T', 0,
  /* 2553 */ 'G', '_', 'Z', 'E', 'X', 'T', 0,
  /* 2560 */ 'L', 'B', 'U', 0,
  /* 2564 */ 'B', 'G', 'E', 'U', 0,
  /* 2569 */ 'M', 'U', 'L', 'H', 'U', 0,
  /* 2575 */ 'S', 'L', 'T', 'I', 'U', 0,
  /* 2581 */ 'F', 'C', 'V', 'T', '_', 'D', '_', 'L', 'U', 0,
  /* 2591 */ 'F', 'C', 'V', 'T', '_', 'S', '_', 'L', 'U', 0,
  /* 2601 */ 'R', 'E', 'M', 'U', 0,
  /* 2606 */ 'M', 'U', 'L', 'H', 'S', 'U', 0,
  /* 2613 */ 'B', 'L', 'T', 'U', 0,
  /* 2618 */ 'S', 'L', 'T', 'U', 0,
  /* 2623 */ 'D', 'I', 'V', 'U', 0,
  /* 2628 */ 'L', 'W', 'U', 0,
  /* 2632 */ 'F', 'C', 'V', 'T', '_', 'D', '_', 'W', 'U', 0,
  /* 2642 */ 'F', 'C', 'V', 'T', '_', 'S', '_', 'W', 'U', 0,
  /* 2652 */ 'G', '_', 'F', 'D', 'I', 'V', 0,
  /* 2659 */ 'G', '_', 'S', 'D', 'I', 'V', 0,
  /* 2666 */ 'G', '_', 'U', 'D', 'I', 'V', 0,
  /* 2673 */ 'S', 'R', 'A', 'W', 0,
  /* 2678 */ 'S', 'U', 'B', 'W', 0,
  /* 2683 */ 'A', 'D', 'D', 'W', 0,
  /* 2688 */ 'S', 'R', 'A', 'I', 'W', 0,
  /* 2694 */ 'A', 'D', 'D', 'I', 'W', 0,
  /* 2700 */ 'S', 'L', 'L', 'I', 'W', 0,
  /* 2706 */ 'S', 'R', 'L', 'I', 'W', 0,
  /* 2712 */ 'F', 'L', 'W', 0,
  /* 2716 */ 'S', 'L', 'L', 'W', 0,
  /* 2721 */ 'S', 'R', 'L', 'W', 0,
  /* 2726 */ 'M', 'U', 'L', 'W', 0,
  /* 2731 */ 'R', 'E', 'M', 'W', 0,
  /* 2736 */ 'G', '_', 'F', 'P', 'O', 'W', 0,
  /* 2743 */ 'C', 'S', 'R', 'R', 'W', 0,
  /* 2749 */ 'F', 'S', 'W', 0,
  /* 2753 */ 'R', 'E', 'M', 'U', 'W', 0,
  /* 2759 */ 'D', 'I', 'V', 'U', 'W', 0,
  /* 2765 */ 'D', 'I', 'V', 'W', 0,
  /* 2770 */ 'S', 'C', '_', 'W', 0,
  /* 2775 */ 'A', 'M', 'O', 'A', 'D', 'D', '_', 'W', 0,
  /* 2784 */ 'A', 'M', 'O', 'A', 'N', 'D', '_', 'W', 0,
  /* 2793 */ 'F', 'C', 'V', 'T', '_', 'D', '_', 'W', 0,
  /* 2802 */ 'A', 'M', 'O', 'M', 'I', 'N', '_', 'W', 0,
  /* 2811 */ 'A', 'M', 'O', 'S', 'W', 'A', 'P', '_', 'W', 0,
  /* 2821 */ 'L', 'R', '_', 'W', 0,
  /* 2826 */ 'A', 'M', 'O', 'O', 'R', '_', 'W', 0,
  /* 2834 */ 'A', 'M', 'O', 'X', 'O', 'R', '_', 'W', 0,
  /* 2843 */ 'F', 'C', 'V', 'T', '_', 'S', '_', 'W', 0,
  /* 2852 */ 'A', 'M', 'O', 'M', 'I', 'N', 'U', '_', 'W', 0,
  /* 2862 */ 'A', 'M', 'O', 'M', 'A', 'X', 'U', '_', 'W', 0,
  /* 2872 */ 'A', 'M', 'O', 'M', 'A', 'X', '_', 'W', 0,
  /* 2881 */ 'F', 'M', 'V', '_', 'X', '_', 'W', 0,
  /* 2889 */ 'G', '_', 'F', 'R', 'A', 'M', 'E', '_', 'I', 'N', 'D', 'E', 'X', 0,
  /* 2903 */ 'F', 'M', 'V', '_', 'D', '_', 'X', 0,
  /* 2911 */ 'F', 'M', 'V', '_', 'W', '_', 'X', 0,
  /* 2919 */ 'C', 'O', 'P', 'Y', 0,
  /* 2924 */ 'S', 'e', 'l', 'e', 'c', 't', 0,
};

extern const unsigned RISCVInstrNameIndices[] = {
    693U, 1512U, 1522U, 792U, 783U, 877U, 575U, 590U, 
    555U, 604U, 2072U, 528U, 471U, 2919U, 496U, 2495U, 
    117U, 1587U, 854U, 2463U, 151U, 2452U, 507U, 1647U, 
    1634U, 1951U, 2332U, 2356U, 813U, 833U, 101U, 39U, 
    1467U, 2659U, 2666U, 1498U, 1505U, 111U, 2018U, 2012U, 
    553U, 2889U, 538U, 2300U, 2034U, 2510U, 2051U, 2474U, 
    2023U, 2519U, 87U, 520U, 142U, 2319U, 45U, 2089U, 
    2544U, 67U, 2441U, 2429U, 2485U, 625U, 2537U, 2553U, 
    801U, 1983U, 1976U, 1627U, 1620U, 2310U, 484U, 457U, 
    1563U, 1555U, 1579U, 1571U, 641U, 633U, 94U, 32U, 
    1460U, 16U, 2652U, 1491U, 2736U, 1674U, 8U, 618U, 
    0U, 568U, 2529U, 57U, 712U, 737U, 1602U, 1611U, 
    1596U, 768U, 1937U, 2405U, 2384U, 1995U, 97U, 664U, 
    2694U, 2683U, 1538U, 1659U, 225U, 1689U, 1027U, 898U, 
    2775U, 1815U, 1186U, 1342U, 234U, 1701U, 1042U, 910U, 
    2784U, 1827U, 1201U, 1354U, 398U, 1782U, 1144U, 991U, 
    2862U, 1908U, 1303U, 1435U, 431U, 1795U, 1160U, 1004U, 
    2872U, 1921U, 1319U, 1448U, 378U, 1769U, 1128U, 978U, 
    2852U, 1895U, 1287U, 1422U, 280U, 1713U, 1057U, 922U, 
    2802U, 1839U, 1216U, 1366U, 319U, 1746U, 1099U, 955U, 
    2826U, 1872U, 1258U, 1399U, 298U, 1725U, 1072U, 934U, 
    2811U, 1851U, 1231U, 1378U, 327U, 1757U, 1113U, 966U, 
    2834U, 1883U, 1272U, 1410U, 113U, 669U, 75U, 1933U, 
    492U, 2564U, 2380U, 2613U, 503U, 81U, 657U, 2066U, 
    721U, 2743U, 746U, 2655U, 2623U, 2759U, 2765U, 761U, 
    807U, 201U, 2140U, 336U, 2225U, 1473U, 2581U, 2164U, 
    2793U, 2632U, 368U, 2248U, 264U, 2194U, 345U, 1482U, 
    2591U, 2843U, 2642U, 388U, 2258U, 415U, 2275U, 408U, 
    2268U, 465U, 753U, 308U, 2219U, 107U, 243U, 2173U, 
    354U, 2234U, 2712U, 208U, 2147U, 424U, 2284U, 273U, 
    2203U, 179U, 2123U, 257U, 2187U, 2903U, 2911U, 449U, 
    2881U, 216U, 2155U, 187U, 2131U, 168U, 289U, 2210U, 
    440U, 2291U, 249U, 2179U, 360U, 2240U, 172U, 2116U, 
    2749U, 779U, 1990U, 26U, 2560U, 108U, 674U, 638U, 
    2571U, 314U, 1738U, 1088U, 947U, 2821U, 1864U, 1247U, 
    1391U, 733U, 2713U, 2628U, 681U, 1463U, 636U, 2606U, 
    2569U, 2726U, 2009U, 708U, 1942U, 130U, 866U, 2346U, 
    1494U, 2601U, 2753U, 2731U, 29U, 196U, 1681U, 1016U, 
    890U, 2770U, 1807U, 1175U, 1334U, 169U, 649U, 882U, 
    697U, 2700U, 2716U, 2425U, 728U, 2575U, 2618U, 22U, 
    652U, 2688U, 2673U, 886U, 702U, 2706U, 2721U, 35U, 
    2678U, 2750U, 687U, 2924U, 2014U, 707U, 
};

static inline void InitRISCVMCInstrInfo(MCInstrInfo *II) {
  II->InitMCInstrInfo(RISCVInsts, RISCVInstrNameIndices, RISCVInstrNameData, 334);
}

} // end llvm namespace
#endif // GET_INSTRINFO_MC_DESC

#ifdef GET_INSTRINFO_HEADER
#undef GET_INSTRINFO_HEADER
namespace llvm {
struct RISCVGenInstrInfo : public TargetInstrInfo {
  explicit RISCVGenInstrInfo(int CFSetupOpcode = -1, int CFDestroyOpcode = -1, int CatchRetOpcode = -1, int ReturnOpcode = -1);
  ~RISCVGenInstrInfo() override = default;
};
} // end llvm namespace
#endif // GET_INSTRINFO_HEADER

#ifdef GET_INSTRINFO_CTOR_DTOR
#undef GET_INSTRINFO_CTOR_DTOR
namespace llvm {
extern const MCInstrDesc RISCVInsts[];
extern const unsigned RISCVInstrNameIndices[];
extern const char RISCVInstrNameData[];
RISCVGenInstrInfo::RISCVGenInstrInfo(int CFSetupOpcode, int CFDestroyOpcode, int CatchRetOpcode, int ReturnOpcode)
  : TargetInstrInfo(CFSetupOpcode, CFDestroyOpcode, CatchRetOpcode, ReturnOpcode) {
  InitMCInstrInfo(RISCVInsts, RISCVInstrNameIndices, RISCVInstrNameData, 334);
}
} // end llvm namespace
#endif // GET_INSTRINFO_CTOR_DTOR

#ifdef GET_INSTRINFO_OPERAND_ENUM
#undef GET_INSTRINFO_OPERAND_ENUM
namespace llvm {
namespace RISCV {
namespace OpName {
enum {
OPERAND_LAST
};
} // end namespace OpName
} // end namespace RISCV
} // end namespace llvm
#endif //GET_INSTRINFO_OPERAND_ENUM

#ifdef GET_INSTRINFO_NAMED_OPS
#undef GET_INSTRINFO_NAMED_OPS
namespace llvm {
namespace RISCV {
LLVM_READONLY
int16_t getNamedOperandIdx(uint16_t Opcode, uint16_t NamedIdx) {
  return -1;
}
} // end namespace RISCV
} // end namespace llvm
#endif //GET_INSTRINFO_NAMED_OPS

#ifdef GET_INSTRINFO_OPERAND_TYPES_ENUM
#undef GET_INSTRINFO_OPERAND_TYPES_ENUM
namespace llvm {
namespace RISCV {
namespace OpTypes {
enum OperandType {
  MEMii = 0,
  f32imm = 1,
  f64imm = 2,
  fencearg = 3,
  i16imm = 4,
  i1imm = 5,
  i32imm = 6,
  i64imm = 7,
  i8imm = 8,
  ixlenimm = 9,
  simm12 = 10,
  simm13_lsb0 = 11,
  simm21_lsb0 = 12,
  type0 = 13,
  type1 = 14,
  type2 = 15,
  type3 = 16,
  type4 = 17,
  type5 = 18,
  uimm12 = 19,
  uimm20 = 20,
  uimm5 = 21,
  uimmlog2xlen = 22,
  OPERAND_TYPE_LIST_END
};
} // end namespace OpTypes
} // end namespace RISCV
} // end namespace llvm
#endif // GET_INSTRINFO_OPERAND_TYPES_ENUM

