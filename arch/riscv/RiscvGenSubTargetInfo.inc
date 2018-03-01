/*===- TableGen'erated file -------------------------------------*- C++ -*-===*\
|*                                                                            *|
|* Subtarget Enumeration Source Fragment                                      *|
|*                                                                            *|
|* Automatically generated file, do not edit!                                 *|
|*                                                                            *|
\*===----------------------------------------------------------------------===*/


#ifdef GET_SUBTARGETINFO_ENUM
#undef GET_SUBTARGETINFO_ENUM

namespace llvm {
namespace RISCV {
enum {
  Feature64Bit = 0,
  FeatureStdExtA = 1,
  FeatureStdExtD = 2,
  FeatureStdExtF = 3,
  FeatureStdExtM = 4
};
} // end namespace RISCV
} // end namespace llvm

#endif // GET_SUBTARGETINFO_ENUM


#ifdef GET_SUBTARGETINFO_MC_DESC
#undef GET_SUBTARGETINFO_MC_DESC

namespace llvm {
// Sorted (by key) array of values for CPU features.
extern const llvm::SubtargetFeatureKV RISCVFeatureKV[] = {
  { "64bit", "Implements RV64", { RISCV::Feature64Bit }, { } },
  { "a", "'A' (Atomic Instructions)", { RISCV::FeatureStdExtA }, { } },
  { "d", "'D' (Double-Precision Floating-Point)", { RISCV::FeatureStdExtD }, { RISCV::FeatureStdExtF } },
  { "f", "'F' (Single-Precision Floating-Point)", { RISCV::FeatureStdExtF }, { } },
  { "m", "'M' (Integer Multiplication and Division)", { RISCV::FeatureStdExtM }, { } }
};

// Sorted (by key) array of values for CPU subtype.
extern const llvm::SubtargetFeatureKV RISCVSubTypeKV[] = {
  { "generic-rv32", "Select the generic-rv32 processor", { }, { } },
  { "generic-rv64", "Select the generic-rv64 processor", { RISCV::Feature64Bit }, { } }
};

#ifdef DBGFIELD
#error "<target>GenSubtargetInfo.inc requires a DBGFIELD macro"
#endif
#ifndef NDEBUG
#define DBGFIELD(x) x,
#else
#define DBGFIELD(x)
#endif

// ===============================================================
// Data tables for the new per-operand machine model.

// {ProcResourceIdx, Cycles}
extern const llvm::MCWriteProcResEntry RISCVWriteProcResTable[] = {
  { 0,  0}, // Invalid
}; // RISCVWriteProcResTable

// {Cycles, WriteResourceID}
extern const llvm::MCWriteLatencyEntry RISCVWriteLatencyTable[] = {
  { 0,  0}, // Invalid
}; // RISCVWriteLatencyTable

// {UseIdx, WriteResourceID, Cycles}
extern const llvm::MCReadAdvanceEntry RISCVReadAdvanceTable[] = {
  {0,  0,  0}, // Invalid
}; // RISCVReadAdvanceTable

static const llvm::MCSchedModel NoSchedModel = {
  MCSchedModel::DefaultIssueWidth,
  MCSchedModel::DefaultMicroOpBufferSize,
  MCSchedModel::DefaultLoopMicroOpBufferSize,
  MCSchedModel::DefaultLoadLatency,
  MCSchedModel::DefaultHighLatency,
  MCSchedModel::DefaultMispredictPenalty,
  false, // PostRAScheduler
  false, // CompleteModel
  0, // Processor ID
  nullptr, nullptr, 0, 0, // No instruction-level machine model.
  nullptr}; // No Itinerary

// Sorted (by key) array of itineraries for CPU subtype.
extern const llvm::SubtargetInfoKV RISCVProcSchedKV[] = {
  { "generic-rv32", (const void *)&NoSchedModel },
  { "generic-rv64", (const void *)&NoSchedModel }
};
#undef DBGFIELD
static inline MCSubtargetInfo *createRISCVMCSubtargetInfoImpl(const Triple &TT, StringRef CPU, StringRef FS) {
  return new MCSubtargetInfo(TT, CPU, FS, RISCVFeatureKV, RISCVSubTypeKV, 
                      RISCVProcSchedKV, RISCVWriteProcResTable, RISCVWriteLatencyTable, RISCVReadAdvanceTable, 
                      nullptr, nullptr, nullptr);
}

} // end namespace llvm

#endif // GET_SUBTARGETINFO_MC_DESC


#ifdef GET_SUBTARGETINFO_TARGET_DESC
#undef GET_SUBTARGETINFO_TARGET_DESC

#include "llvm/Support/Debug.h"
#include "llvm/Support/raw_ostream.h"

// ParseSubtargetFeatures - Parses features string setting specified
// subtarget options.
void llvm::RISCVSubtarget::ParseSubtargetFeatures(StringRef CPU, StringRef FS) {
  DEBUG(dbgs() << "\nFeatures:" << FS);
  DEBUG(dbgs() << "\nCPU:" << CPU << "\n\n");
  InitMCProcessorInfo(CPU, FS);
  const FeatureBitset& Bits = getFeatureBits();
  if (Bits[RISCV::Feature64Bit]) HasRV64 = true;
  if (Bits[RISCV::FeatureStdExtA]) HasStdExtA = true;
  if (Bits[RISCV::FeatureStdExtD]) HasStdExtD = true;
  if (Bits[RISCV::FeatureStdExtF]) HasStdExtF = true;
  if (Bits[RISCV::FeatureStdExtM]) HasStdExtM = true;
}
#endif // GET_SUBTARGETINFO_TARGET_DESC


#ifdef GET_SUBTARGETINFO_HEADER
#undef GET_SUBTARGETINFO_HEADER

namespace llvm {
class DFAPacketizer;
struct RISCVGenSubtargetInfo : public TargetSubtargetInfo {
  explicit RISCVGenSubtargetInfo(const Triple &TT, StringRef CPU, StringRef FS);
public:
  unsigned resolveSchedClass(unsigned SchedClass,  const MachineInstr *DefMI, const TargetSchedModel *SchedModel) const override;
  DFAPacketizer *createDFAPacketizer(const InstrItineraryData *IID) const;
  unsigned getHwMode() const override;
};
} // end namespace llvm

#endif // GET_SUBTARGETINFO_HEADER


#ifdef GET_SUBTARGETINFO_CTOR
#undef GET_SUBTARGETINFO_CTOR

#include "llvm/CodeGen/TargetSchedule.h"

namespace llvm {
extern const llvm::SubtargetFeatureKV RISCVFeatureKV[];
extern const llvm::SubtargetFeatureKV RISCVSubTypeKV[];
extern const llvm::SubtargetInfoKV RISCVProcSchedKV[];
extern const llvm::MCWriteProcResEntry RISCVWriteProcResTable[];
extern const llvm::MCWriteLatencyEntry RISCVWriteLatencyTable[];
extern const llvm::MCReadAdvanceEntry RISCVReadAdvanceTable[];
RISCVGenSubtargetInfo::RISCVGenSubtargetInfo(const Triple &TT, StringRef CPU, StringRef FS)
  : TargetSubtargetInfo(TT, CPU, FS, makeArrayRef(RISCVFeatureKV, 5), makeArrayRef(RISCVSubTypeKV, 2), 
                        RISCVProcSchedKV, RISCVWriteProcResTable, RISCVWriteLatencyTable, RISCVReadAdvanceTable, 
                        nullptr, nullptr, nullptr) {}

unsigned RISCVGenSubtargetInfo
::resolveSchedClass(unsigned SchedClass, const MachineInstr *MI, const TargetSchedModel *SchedModel) const {
  report_fatal_error("Expected a variant SchedClass");
} // RISCVGenSubtargetInfo::resolveSchedClass
unsigned RISCVGenSubtargetInfo::getHwMode() const {
  if (checkFeatures("-64bit")) return 1;
  if (checkFeatures("+64bit")) return 2;
  return 0;
}
} // end namespace llvm

#endif // GET_SUBTARGETINFO_CTOR

