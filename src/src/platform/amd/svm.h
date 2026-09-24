#ifndef _SVM_H_
#define _SVM_H_

#include "../../hv_platform.h"
#include "npt.h"

#define MSR_VM_CR               0xC0010114
#define MSR_VM_HSAVE_PA         0xC0010117
#define MSR_EFER                0xC0000080
#define MSR_IA32_FEATURE_CONTROL 0x3A
#define MSR_IA32_APIC_BASE      0x1B
#define MSR_IA32_DEBUGCTL       0x1D9

#define EFER_SVME               (1ULL << 12)
#define VM_CR_SVMDIS            (1ULL << 4)

#define HV_VMMCALL_MAGIC        0x464F5247ULL
#define HV_VMMCALL_DEVIRT       0x01ULL

#define VMEXIT_NMI              0x61
#define VMEXIT_CR4_WRITE        0x14
#define VMEXIT_DR0_READ         0x20
#define VMEXIT_DR7_READ         0x27
#define VMEXIT_DR0_WRITE        0x30
#define VMEXIT_DR7_WRITE        0x37
#define VMEXIT_CPUID            0x72
#define VMEXIT_MSR              0x7C
#define VMEXIT_SHUTDOWN         0x7F
#define VMEXIT_VMRUN            0x80
#define VMEXIT_VMMCALL          0x81
#define VMEXIT_VMLOAD           0x82
#define VMEXIT_VMSAVE           0x83
#define VMEXIT_STGI             0x84
#define VMEXIT_CLGI             0x85
#define VMEXIT_SKINIT           0x86

#define VMEXIT_INVLPGA          0x7A
#define VMEXIT_EXCEPTION_DB     0x41
#define VMEXIT_NPF              0x400

#define VMCB_SSA_EFER           0x4D0
#define VMCB_SSA_CR3            0x550
#define VMCB_SSA_RFLAGS         0x570
#define VMCB_SSA_RIP            0x578
#define VMCB_SSA_RSP            0x5D8
#define VMCB_SSA_RAX            0x5F8

#pragma pack(push, 1)

typedef struct _VMCB_SEGMENT_ATTRIBUTE {
    union {
        USHORT AsUInt16;
        struct {
            USHORT Type : 4;
            USHORT System : 1;
            USHORT Dpl : 2;
            USHORT Present : 1;
            USHORT Available : 1;
            USHORT LongMode : 1;
            USHORT DefaultOperandSize : 1;
            USHORT Granularity : 1;
            USHORT Reserved : 4;
        } Fields;
    };
} VMCB_SEGMENT_ATTRIBUTE, *PVMCB_SEGMENT_ATTRIBUTE;

typedef struct _VMCB_SEGMENT {
    USHORT Selector;
    VMCB_SEGMENT_ATTRIBUTE Attributes;
    ULONG Limit;
    ULONG64 Base;
} VMCB_SEGMENT, *PVMCB_SEGMENT;

typedef struct _VMCB_CONTROL_AREA {
    ULONG InterceptCr;
    ULONG InterceptDr;
    ULONG InterceptException;
    ULONG InterceptMisc1;
    ULONG InterceptMisc2;
    ULONG InterceptMisc3;
    UCHAR Reserved1[36];
    USHORT PauseFilterThreshold;
    USHORT PauseFilterCount;
    ULONG64 IopmBasePa;
    ULONG64 MsrpmBasePa;
    ULONG64 TscOffset;
    ULONG GuestAsid;
    UCHAR TlbControl;
    UCHAR Reserved2[3];
    ULONG64 VirtualIntCtrl;
    ULONG64 InterruptShadow;
    ULONG64 ExitCode;
    ULONG64 ExitInfo1;
    ULONG64 ExitInfo2;
    ULONG ExitIntInfo;
    ULONG ExitIntInfoErr;
    ULONG64 NestedCtl;
    ULONG64 AvicApicBar;
    ULONG64 GhcbPa;
    ULONG64 EventInj;
    ULONG64 NCr3;
    ULONG64 LbrVirtualizationControl;
    ULONG VmcbClean;
    ULONG Reserved3;
    ULONG64 nRip;
    UCHAR NumberOfBytesFetched;
    UCHAR GuestInstructionBytes[15];
    ULONG64 ApicBackingPagePa;
    ULONG64 Reserved4;
    ULONG64 AvicLogicalTablePa;
    ULONG64 AvicPhysicalTablePa;
    ULONG64 Reserved5;
    ULONG64 VmcbSaveStatePointer;
    UCHAR Reserved6[752];
} VMCB_CONTROL_AREA, *PVMCB_CONTROL_AREA;

typedef struct _VMCB_STATE_SAVE_AREA {
    VMCB_SEGMENT Es;
    VMCB_SEGMENT Cs;
    VMCB_SEGMENT Ss;
    VMCB_SEGMENT Ds;
    VMCB_SEGMENT Fs;
    VMCB_SEGMENT Gs;
    VMCB_SEGMENT Gdtr;
    VMCB_SEGMENT Ldtr;
    VMCB_SEGMENT Idtr;
    VMCB_SEGMENT Tr;
    UCHAR Reserved1[43];
    UCHAR Cpl;
    ULONG Reserved2;
    ULONG64 Efer;
    UCHAR Reserved3[112];
    ULONG64 Cr4;
    ULONG64 Cr3;
    ULONG64 Cr0;
    ULONG64 Dr7;
    ULONG64 Dr6;
    ULONG64 Rflags;
    ULONG64 Rip;
    UCHAR Reserved4[88];
    ULONG64 Rsp;
    UCHAR Reserved5[24];
    ULONG64 Rax;
    ULONG64 Star;
    ULONG64 Lstar;
    ULONG64 Cstar;
    ULONG64 Sfmask;
    ULONG64 KernelGsBase;
    ULONG64 SysenterCs;
    ULONG64 SysenterEsp;
    ULONG64 SysenterEip;
    ULONG64 Cr2;
    UCHAR Reserved6[32];
    ULONG64 GPat;
    ULONG64 DbgCtl;
    ULONG64 BrFrom;
    ULONG64 BrTo;
    ULONG64 LastExcpFrom;
    ULONG64 LastExcpTo;
} VMCB_STATE_SAVE_AREA, *PVMCB_STATE_SAVE_AREA;

typedef struct _VMCB {
    VMCB_CONTROL_AREA ControlArea;
    VMCB_STATE_SAVE_AREA StateSaveArea;
    UCHAR Reserved[0x1000 - sizeof(VMCB_CONTROL_AREA) - sizeof(VMCB_STATE_SAVE_AREA)];
} VMCB, *PVMCB;

#pragma pack(pop)

typedef struct _GUEST_CONTEXT {
    ULONG64 Rax;
    ULONG64 Rcx;
    ULONG64 Rdx;
    ULONG64 Rbx;
    ULONG64 Rbp;
    ULONG64 Rsi;
    ULONG64 Rdi;
    ULONG64 R8;
    ULONG64 R9;
    ULONG64 R10;
    ULONG64 R11;
    ULONG64 R12;
    ULONG64 R13;
    ULONG64 R14;
    ULONG64 R15;
} GUEST_CONTEXT, *PGUEST_CONTEXT;

BOOLEAN SvmEnablePhase3(void);
VOID SvmDisablePhase3(void);
BOOLEAN SvmSubvertCore(void);
VOID SvmDevirtualizeCore(void);

USHORT AsmGetCs(void);
USHORT AsmGetDs(void);
USHORT AsmGetEs(void);
USHORT AsmGetSs(void);
USHORT AsmGetFs(void);
USHORT AsmGetGs(void);
USHORT AsmGetLdtr(void);
USHORT AsmGetTr(void);
ULONG64 AsmGetGdtBase(void);
USHORT AsmGetGdtLimit(void);
ULONG64 AsmGetIdtBase(void);
USHORT AsmGetIdtLimit(void);

VOID AsmHypervisorLoop(ULONG64 VmcbPhysical);
VOID AsmVmmcallDevirtualize(void);

VOID SvmSnapshotDispatcherHash(void);

#endif
