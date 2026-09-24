#ifndef HV_COMM_H
#define HV_COMM_H

#include "hv_platform.h"

#define HV_MAGIC_SEED         0x46475248ULL
#define HV_MAGIC_MIX(bootId)  (HV_MAGIC_SEED ^ ((ULONG64)(bootId) * 0x5DEECE66DULL + 0xBULL))

#define HV_CMD_PING          0x01
#define HV_CMD_ATTACH        0x10
#define HV_CMD_READ          0x11
#define HV_CMD_WRITE         0x12
#define HV_CMD_GET_BASE      0x13
#define HV_CMD_DETACH        0x14
#define HV_CMD_MAP_ALLOW     0x15
#define HV_CMD_MAP_BLOCK     0x16
#define HV_CMD_FIND_PROCESS  0x17
#define HV_CMD_DIAG          0x20
#define HV_CMD_STEALTH_STATUS 0x30

#define STEALTH_CPUID_INTERCEPT      (1ULL << 0)
#define STEALTH_HV_BIT_CLEARED       (1ULL << 1)
#define STEALTH_VENDOR_LEAF_CACHED   (1ULL << 2)
#define STEALTH_EXT_LEAVES_ZEROED    (1ULL << 3)
#define STEALTH_SVM_LEAF_ZEROED      (1ULL << 4)
#define STEALTH_80000008_MASKED      (1ULL << 5)
#define STEALTH_VMCR_SVMDIS          (1ULL << 6)
#define STEALTH_SHADOW_EFER_CLEAN    (1ULL << 7)

#define STEALTH_EFER_RDMSR_BIT       (1ULL << 8)
#define STEALTH_EFER_WRMSR_BIT       (1ULL << 9)
#define STEALTH_HSAVE_RDMSR_BIT      (1ULL << 10)
#define STEALTH_HSAVE_WRMSR_BIT      (1ULL << 11)
#define STEALTH_VMCR_RDMSR_BIT       (1ULL << 12)
#define STEALTH_VMCR_WRMSR_BIT       (1ULL << 13)
#define STEALTH_MSRPM_BASE_VALID     (1ULL << 14)
#define STEALTH_IOPM_CONFIGURED      (1ULL << 15)

#define STEALTH_SVM_INSNS_TRAPPED    (1ULL << 20)
#define STEALTH_VMMCALL_TRAPPED      (1ULL << 21)
#define STEALTH_INVLPGA_TRAPPED      (1ULL << 22)
#define STEALTH_SHUTDOWN_INTERCEPT   (1ULL << 23)

#define STEALTH_NPT_ENABLED          (1ULL << 24)
#define STEALTH_NPT_ROOT_VALID       (1ULL << 25)
#define STEALTH_DECOYS_ALLOCATED     (1ULL << 26)
#define STEALTH_DECOY0_INTEGRITY     (1ULL << 27)
#define STEALTH_DRIVER_IMAGE_TRACKED (1ULL << 28)
#define STEALTH_BIGPOOL_CLEANED      (1ULL << 29)
#define STEALTH_IOMMU_CONSISTENT     (1ULL << 30)
#define STEALTH_ROLLING_MAGIC_VALID  (1ULL << 31)

#define STEALTH_KILL_SWITCH_OK       (1ULL << 32)
#define STEALTH_ALL_CORES_LIVE       (1ULL << 33)
#define STEALTH_HOST_CR3_VALID       (1ULL << 34)
#define STEALTH_SCRATCH_PT_VALID     (1ULL << 35)
#define STEALTH_EPROCESS_OFFSETS_OK  (1ULL << 36)
#define STEALTH_PHYS_MEM_RANGES_OK   (1ULL << 37)
#define STEALTH_LOG_RING_ALIVE       (1ULL << 38)
#define STEALTH_GUEST_ASID_VALID     (1ULL << 39)

#define STEALTH_ALL_OK               0x000000FFFFF0FFFFULL

#define HV_STATUS_OK         0x00000001
#define HV_STATUS_FAIL       0x00000000
#define HV_STATUS_NO_TARGET  0x00000002
#define HV_STATUS_BAD_VA     0x00000003
#define HV_STATUS_BAD_CMD    0x000000FF

ULONG64 HvCommDispatch(ULONG64 command, ULONG64 arg1, ULONG64 arg2,
                        ULONG64 arg3, ULONG64 guestCr3);

ULONG64 HvTranslateGuestVa(ULONG64 processCr3, ULONG64 guestVa);

BOOLEAN HvReadVirtualMemory(ULONG64 targetCr3, ULONG64 sourceVa,
                             ULONG64 callerCr3, ULONG64 destVa,
                             ULONG64 size);

BOOLEAN HvWriteVirtualMemory(ULONG64 targetCr3, ULONG64 destVa,
                              ULONG64 callerCr3, ULONG64 sourceVa,
                              ULONG64 size);

#endif
