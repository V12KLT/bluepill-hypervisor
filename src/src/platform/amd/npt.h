#ifndef _NPT_H_
#define _NPT_H_

#include "../../hv_platform.h"

#define NPT_ENTRIES_PER_TABLE   512

#define NPT_LARGE_PAGE_SIZE     0x200000ULL
#define NPT_PAGE_SIZE           0x1000ULL

#define NPT_PDPT_COUNT          4

#pragma pack(push, 1)
typedef union _NPT_PTE {
    ULONG64 AsUInt64;
    struct {
        ULONG64 Present : 1;
        ULONG64 ReadWrite : 1;
        ULONG64 User : 1;
        ULONG64 WriteThrough : 1;
        ULONG64 CacheDisable : 1;
        ULONG64 Accessed : 1;
        ULONG64 Dirty : 1;
        ULONG64 PageSize : 1;
        ULONG64 Global : 1;
        ULONG64 Available1 : 3;
        ULONG64 PageFrameNumber : 40;
        ULONG64 Available2 : 11;
        ULONG64 NoExecute : 1;
    } Fields;
} NPT_PTE, *PNPT_PTE;
#pragma pack(pop)

C_ASSERT(sizeof(NPT_PTE) == 8);

ULONG64 NptBuildIdentityMap(void);

VOID NptFree(void);

BOOLEAN NptHandleNestedPageFault(ULONG64 ExitInfo1, ULONG64 FaultingGpa);

BOOLEAN NptHidePhysicalPage(ULONG64 TargetHpa);

BOOLEAN NptPreallocateSplitPages(ULONG maxPages);

#define NPT_SPLIT_POOL_MAX  128

extern PVOID   g_NptSplitPool[];
extern PHYSICAL_ADDRESS g_NptSplitPoolPhys[];
extern volatile LONG g_NptSplitPoolNext;
extern LONG g_NptSplitPoolCount;

#endif
