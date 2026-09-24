#include "npt.h"
#include "svm.h"

PVOID            g_NptSplitPool[NPT_SPLIT_POOL_MAX];
PHYSICAL_ADDRESS g_NptSplitPoolPhys[NPT_SPLIT_POOL_MAX];
volatile LONG    g_NptSplitPoolNext = 0;
LONG             g_NptSplitPoolCount = 0;

static PVOID NptFindSplitPoolVa(ULONG64 pa) {
    LONG bound = g_NptSplitPoolCount;
    for (LONG i = 0; i < bound; i++) {
        if (g_NptSplitPoolPhys[i].QuadPart == (LONGLONG)pa) {
            return g_NptSplitPool[i];
        }
    }
    return NULL;
}

BOOLEAN NptPreallocateSplitPages(ULONG maxPages) {
    if (maxPages > NPT_SPLIT_POOL_MAX) maxPages = NPT_SPLIT_POOL_MAX;

    for (ULONG i = 0; i < maxPages; i++) {
        g_NptSplitPool[i] = HvAllocatePhysicalMemory(NPT_PAGE_SIZE, &g_NptSplitPoolPhys[i]);
        if (!g_NptSplitPool[i]) {
            LOG_ERROR("NPT: Split pool allocation failed at page %u/%u", i, maxPages);
            g_NptSplitPoolCount = (LONG)i;
            return (i > 0);
        }
    }
    g_NptSplitPoolCount = (LONG)maxPages;
    g_NptSplitPoolNext = 0;
    LOG_OK("NPT: Pre-allocated %u pages for split pool.", maxPages);
    return TRUE;
}

static VOID NptFreeSplitPool(void) {
    for (LONG i = 0; i < g_NptSplitPoolCount; i++) {
        if (g_NptSplitPool[i]) {
            HvFreePhysicalMemory(g_NptSplitPool[i]);
            g_NptSplitPool[i] = NULL;
        }
    }
    g_NptSplitPoolCount = 0;
    g_NptSplitPoolNext = 0;
}

static PVOID NptAllocateFromPool(PPHYSICAL_ADDRESS outPhysical) {
    LONG idx = InterlockedIncrement(&g_NptSplitPoolNext) - 1;
    if (idx >= g_NptSplitPoolCount) {
        InterlockedDecrement(&g_NptSplitPoolNext);
        LOG_ERROR("NPT: Split page pool exhausted! Increase NPT_SPLIT_POOL_MAX.");
        return NULL;
    }
    *outPhysical = g_NptSplitPoolPhys[idx];
    return g_NptSplitPool[idx];
}

static BOOLEAN NptSupports1GBPages(void) {
    int cpuInfo[4];
    __cpuid(cpuInfo, 0x80000001);
    return (cpuInfo[3] & (1 << 26)) != 0;
}

static BOOLEAN NptIsSupported(void) {
    int cpuInfo[4];
    __cpuid(cpuInfo, 0x8000000A);
    return (cpuInfo[3] & 1) != 0;
}

ULONG64 NptBuildIdentityMap(void) {
    ULONG i, j, k;

    if (!NptIsSupported()) {
        LOG_ERROR("NPT (Nested Page Tables) not supported by CPU!");
        return 0;
    }

    BOOLEAN use1GBPages = NptSupports1GBPages();
    if (use1GBPages) {
        LOG_INFO("NPT: CPU supports 1GB pages - using optimized identity map.");
    } else {
        LOG_INFO("NPT: CPU does NOT support 1GB pages - using 2MB pages.");
    }

    g_Hv.nptPml4 = HvAllocatePhysicalMemory(NPT_PAGE_SIZE, &g_Hv.nptPml4Physical);
    if (!g_Hv.nptPml4) {
        LOG_ERROR("NPT: Failed to allocate PML4!");
        return 0;
    }

    PNPT_PTE pml4 = (PNPT_PTE)g_Hv.nptPml4;

    g_Hv.nptPdptCount = NPT_PDPT_COUNT;
    g_Hv.nptPdptPages = (PVOID*)ExAllocatePoolWithTag(
        NonPagedPool, sizeof(PVOID) * NPT_PDPT_COUNT, HV_TAG);
    if (!g_Hv.nptPdptPages) {
        LOG_ERROR("NPT: Failed to allocate PDPT tracking array!");
        NptFree();
        return 0;
    }
    RtlSecureZeroMemory(g_Hv.nptPdptPages, sizeof(PVOID) * NPT_PDPT_COUNT);

    if (use1GBPages) {

        g_Hv.nptPdCount = 0;
        g_Hv.nptPdPages = NULL;
    } else {

        g_Hv.nptPdCount = NPT_PDPT_COUNT * NPT_ENTRIES_PER_TABLE;
        g_Hv.nptPdPages = (PVOID*)ExAllocatePoolWithTag(
            NonPagedPool, sizeof(PVOID) * g_Hv.nptPdCount, HV_TAG);
        if (!g_Hv.nptPdPages) {
            LOG_ERROR("NPT: Failed to allocate PD tracking array!");
            NptFree();
            return 0;
        }
        RtlSecureZeroMemory(g_Hv.nptPdPages, sizeof(PVOID) * g_Hv.nptPdCount);
    }

    for (i = 0; i < NPT_PDPT_COUNT; i++) {

        PHYSICAL_ADDRESS pdptPhysical;
        g_Hv.nptPdptPages[i] = HvAllocatePhysicalMemory(NPT_PAGE_SIZE, &pdptPhysical);
        if (!g_Hv.nptPdptPages[i]) {
            LOG_ERROR("NPT: Failed to allocate PDPT %u!", i);
            NptFree();
            return 0;
        }

        pml4[i].AsUInt64 = 0;
        pml4[i].Fields.Present = 1;
        pml4[i].Fields.ReadWrite = 1;
        pml4[i].Fields.User = 1;
        pml4[i].Fields.Accessed = 1;
        pml4[i].Fields.PageFrameNumber = pdptPhysical.QuadPart >> 12;

        PNPT_PTE pdpt = (PNPT_PTE)g_Hv.nptPdptPages[i];

        if (use1GBPages) {

            for (j = 0; j < NPT_ENTRIES_PER_TABLE; j++) {

                ULONG64 physAddr = ((ULONG64)i * NPT_ENTRIES_PER_TABLE + j) * 0x40000000ULL;

                pdpt[j].AsUInt64 = 0;
                pdpt[j].Fields.Present = 1;
                pdpt[j].Fields.ReadWrite = 1;
                pdpt[j].Fields.User = 1;
                pdpt[j].Fields.Accessed = 1;
                pdpt[j].Fields.Dirty = 1;
                pdpt[j].Fields.PageSize = 1;
                pdpt[j].Fields.PageFrameNumber = physAddr >> 12;
            }
        } else {

            for (j = 0; j < NPT_ENTRIES_PER_TABLE; j++) {
                ULONG pdIndex = i * NPT_ENTRIES_PER_TABLE + j;

                PHYSICAL_ADDRESS pdPhysical;
                g_Hv.nptPdPages[pdIndex] = HvAllocatePhysicalMemory(NPT_PAGE_SIZE, &pdPhysical);
                if (!g_Hv.nptPdPages[pdIndex]) {
                    LOG_ERROR("NPT: Failed to allocate PD[%u][%u]!", i, j);
                    NptFree();
                    return 0;
                }

                pdpt[j].AsUInt64 = 0;
                pdpt[j].Fields.Present = 1;
                pdpt[j].Fields.ReadWrite = 1;
                pdpt[j].Fields.User = 1;
                pdpt[j].Fields.Accessed = 1;
                pdpt[j].Fields.PageFrameNumber = pdPhysical.QuadPart >> 12;

                PNPT_PTE pd = (PNPT_PTE)g_Hv.nptPdPages[pdIndex];

                for (k = 0; k < NPT_ENTRIES_PER_TABLE; k++) {
                    ULONG64 physAddr = ((ULONG64)pdIndex * NPT_ENTRIES_PER_TABLE + k) * NPT_LARGE_PAGE_SIZE;

                    pd[k].AsUInt64 = 0;
                    pd[k].Fields.Present = 1;
                    pd[k].Fields.ReadWrite = 1;
                    pd[k].Fields.User = 1;
                    pd[k].Fields.Accessed = 1;
                    pd[k].Fields.Dirty = 1;
                    pd[k].Fields.PageSize = 1;
                    pd[k].Fields.PageFrameNumber = physAddr >> 12;
                }
            }
        }
    }

    if (use1GBPages) {
        LOG_OK("NPT: Identity map built. PML4 PA=0x%llx, Coverage=%uTB (1GB pages)",
               g_Hv.nptPml4Physical.QuadPart,
               (NPT_PDPT_COUNT * 512) / 1024);
    } else {
        LOG_OK("NPT: Identity map built. PML4 PA=0x%llx, Coverage=%uTB (2MB pages)",
               g_Hv.nptPml4Physical.QuadPart,
               (NPT_PDPT_COUNT * 512) / 1024);
    }

    return g_Hv.nptPml4Physical.QuadPart;
}

VOID NptFree(void) {
    ULONG i;

    NptFreeSplitPool();

    if (g_Hv.nptPdPages) {
        for (i = 0; i < g_Hv.nptPdCount; i++) {
            if (g_Hv.nptPdPages[i]) {
                HvFreePhysicalMemory(g_Hv.nptPdPages[i]);
                g_Hv.nptPdPages[i] = NULL;
            }
        }
        ExFreePoolWithTag(g_Hv.nptPdPages, HV_TAG);
        g_Hv.nptPdPages = NULL;
        g_Hv.nptPdCount = 0;
    }

    if (g_Hv.nptPdptPages) {
        for (i = 0; i < g_Hv.nptPdptCount; i++) {
            if (g_Hv.nptPdptPages[i]) {
                HvFreePhysicalMemory(g_Hv.nptPdptPages[i]);
                g_Hv.nptPdptPages[i] = NULL;
            }
        }
        ExFreePoolWithTag(g_Hv.nptPdptPages, HV_TAG);
        g_Hv.nptPdptPages = NULL;
        g_Hv.nptPdptCount = 0;
    }

    if (g_Hv.nptPml4) {
        HvFreePhysicalMemory(g_Hv.nptPml4);
        g_Hv.nptPml4 = NULL;
        g_Hv.nptPml4Physical.QuadPart = 0;
    }
}

BOOLEAN NptForceRestoreIdentity(ULONG64 FaultingGpa) {
    ULONG pml4Index = (ULONG)((FaultingGpa >> 39) & 0x1FF);
    ULONG pdptIndex = (ULONG)((FaultingGpa >> 30) & 0x1FF);
    ULONG pdIndex   = (ULONG)((FaultingGpa >> 21) & 0x1FF);
    ULONG ptIndex   = (ULONG)((FaultingGpa >> 12) & 0x1FF);

    if (pml4Index >= NPT_PDPT_COUNT || !g_Hv.nptPml4)
        return FALSE;

    PNPT_PTE pml4 = (PNPT_PTE)g_Hv.nptPml4;
    if (!pml4[pml4Index].Fields.Present)
        return FALSE;

    PNPT_PTE pdpt = (PNPT_PTE)g_Hv.nptPdptPages[pml4Index];
    if (!pdpt || pdpt[pdptIndex].Fields.PageSize)
        return FALSE;

    ULONG64 pdPhysAddr = pdpt[pdptIndex].Fields.PageFrameNumber << 12;

    PNPT_PTE pd = (PNPT_PTE)NptFindSplitPoolVa(pdPhysAddr);
    if (!pd || pd[pdIndex].Fields.PageSize)
        return FALSE;

    ULONG64 ptPhysAddr = pd[pdIndex].Fields.PageFrameNumber << 12;
    PNPT_PTE pt = (PNPT_PTE)NptFindSplitPoolVa(ptPhysAddr);
    if (!pt)
        return FALSE;

    ULONG64 realPfn = FaultingGpa >> 12;

    NPT_PTE newEntry;
    newEntry.AsUInt64 = pt[ptIndex].AsUInt64;
    newEntry.Fields.PageFrameNumber = realPfn;
    newEntry.Fields.NoExecute = 0;
    newEntry.Fields.ReadWrite = 1;
    newEntry.Fields.Present = 1;
    pt[ptIndex].AsUInt64 = newEntry.AsUInt64;
    return TRUE;
}

BOOLEAN NptHandleNestedPageFault(ULONG64 ExitInfo1, ULONG64 FaultingGpa) {
    ULONG core = KeGetCurrentProcessorNumber();

    if (ExitInfo1 & 0x10) {

        ULONG pml4Index = (ULONG)((FaultingGpa >> 39) & 0x1FF);
        ULONG pdptIndex = (ULONG)((FaultingGpa >> 30) & 0x1FF);
        ULONG pdIndex   = (ULONG)((FaultingGpa >> 21) & 0x1FF);
        ULONG ptIndex   = (ULONG)((FaultingGpa >> 12) & 0x1FF);

        if (pml4Index < NPT_PDPT_COUNT && g_Hv.nptPml4) {
            PNPT_PTE pml4 = (PNPT_PTE)g_Hv.nptPml4;
            if (pml4[pml4Index].Fields.Present) {
                PNPT_PTE pdpt = (PNPT_PTE)g_Hv.nptPdptPages[pml4Index];
                if (pdpt && !pdpt[pdptIndex].Fields.PageSize) {
                    ULONG64 pdPhysAddr = pdpt[pdptIndex].Fields.PageFrameNumber << 12;

                    PNPT_PTE pd = (PNPT_PTE)NptFindSplitPoolVa(pdPhysAddr);
                    if (pd && !pd[pdIndex].Fields.PageSize) {
                        ULONG64 ptPhysAddr = pd[pdIndex].Fields.PageFrameNumber << 12;
                        PNPT_PTE pt = (PNPT_PTE)NptFindSplitPoolVa(ptPhysAddr);
                        if (pt) {

                            NPT_PTE snapshot;
                            snapshot.AsUInt64 = pt[ptIndex].AsUInt64;

                            BOOLEAN isDecoy = FALSE;
                            for (int d = 0; d < 4; d++) {
                                if (snapshot.Fields.PageFrameNumber == (g_Hv.decoyPagesPhysical[d].QuadPart >> 12)) {
                                    isDecoy = TRUE;
                                    break;
                                }
                            }
                            if (isDecoy) {

                                ULONG64 realHpa = FaultingGpa & ~0xFFFULL;
                                ULONG64 realPfn = realHpa >> 12;

                                NPT_PTE newEntry;
                                newEntry.AsUInt64 = snapshot.AsUInt64;
                                newEntry.Fields.PageFrameNumber = realPfn;
                                newEntry.Fields.NoExecute = 0;
                                newEntry.Fields.ReadWrite = 1;
                                pt[ptIndex].AsUInt64 = newEntry.AsUInt64;

                                g_Hv.perCpu[core].savedRealPfn = realPfn;
                                InterlockedExchange(&g_Hv.perCpu[core].singleStepAge, 0);

                                g_Hv.perCpu[core].lastModifiedPte = &pt[ptIndex];
                                g_Hv.perCpu[core].singleStepForNpt = TRUE;

                                PVMCB vmcb = (PVMCB)g_Hv.perCpu[core].guestVmcb;
                                vmcb->StateSaveArea.Rflags |= 0x100;
                                vmcb->ControlArea.TlbControl = 1;

                                return TRUE;
                            }

                            if (snapshot.Fields.Present) {
                                ULONG64 gpaPfn = FaultingGpa >> 12;
                                if (snapshot.Fields.PageFrameNumber == gpaPfn) {

                                    return TRUE;
                                }

                                return TRUE;
                            }
                        }
                    }
                }
            }
        }
    }

    UNREFERENCED_PARAMETER(FaultingGpa);
    return FALSE;
}

BOOLEAN NptHidePhysicalPageSafe(ULONG64 TargetHpa, PHV_STATE hvState) {

    {
        ULONG64 targetPageBase = TargetHpa & ~0xFFFULL;

        if (targetPageBase == (hvState->nptPml4Physical.QuadPart & ~0xFFFULL)) {
            return TRUE;
        }

        if (hvState->nptPdptPages) {
            for (ULONG i = 0; i < hvState->nptPdptCount; i++) {
                if (hvState->nptPdptPages[i]) {
                    PHYSICAL_ADDRESS pdptPa = MmGetPhysicalAddress(hvState->nptPdptPages[i]);
                    if (targetPageBase == (pdptPa.QuadPart & ~0xFFFULL)) {
                        return TRUE;
                    }
                }
            }
        }

        for (LONG sp = 0; sp < g_NptSplitPoolCount; sp++) {
            if (g_NptSplitPool[sp]) {
                if (targetPageBase == (g_NptSplitPoolPhys[sp].QuadPart & ~0xFFFULL)) {
                    return TRUE;
                }
            }
        }

        for (int d = 0; d < 4; d++) {
            if (hvState->decoyPages[d] &&
                targetPageBase == (hvState->decoyPagesPhysical[d].QuadPart & ~0xFFFULL)) {
                return TRUE;
            }
        }

        if (hvState->hostCr3) {
            PHYSICAL_ADDRESS hcr3Pa = MmGetPhysicalAddress(hvState->hostCr3);
            if (targetPageBase == (hcr3Pa.QuadPart & ~0xFFFULL)) {
                return TRUE;
            }
        }
        if (hvState->scratchPt) {
            PHYSICAL_ADDRESS pa = MmGetPhysicalAddress(hvState->scratchPt);
            if (targetPageBase == (pa.QuadPart & ~0xFFFULL)) {
                return TRUE;
            }
        }
        if (hvState->scratchPd) {
            PHYSICAL_ADDRESS pa = MmGetPhysicalAddress(hvState->scratchPd);
            if (targetPageBase == (pa.QuadPart & ~0xFFFULL)) {
                return TRUE;
            }
        }
        if (hvState->scratchPdpt) {
            PHYSICAL_ADDRESS pa = MmGetPhysicalAddress(hvState->scratchPdpt);
            if (targetPageBase == (pa.QuadPart & ~0xFFFULL)) {
                return TRUE;
            }
        }
    }

    ULONG pml4Index = (ULONG)((TargetHpa >> 39) & 0x1FF);
    ULONG pdptIndex = (ULONG)((TargetHpa >> 30) & 0x1FF);
    ULONG pdIndex   = (ULONG)((TargetHpa >> 21) & 0x1FF);
    ULONG ptIndex   = (ULONG)((TargetHpa >> 12) & 0x1FF);

    if (pml4Index >= NPT_PDPT_COUNT || !hvState->nptPml4) {
        return FALSE;
    }

    PNPT_PTE pml4 = (PNPT_PTE)hvState->nptPml4;
    if (!pml4[pml4Index].Fields.Present) {
        return FALSE;
    }

    if (!hvState->nptPdptPages || !hvState->nptPdptPages[pml4Index]) {
        return FALSE;
    }

    PNPT_PTE pdpt = (PNPT_PTE)hvState->nptPdptPages[pml4Index];

    if (pdpt[pdptIndex].Fields.PageSize) {

        ULONG64 baseAddr1GB = pdpt[pdptIndex].Fields.PageFrameNumber << 12;

        PHYSICAL_ADDRESS pdPhysical;
        PVOID pdPage = NptAllocateFromPool(&pdPhysical);
        if (!pdPage) {
            return FALSE;
        }

        PNPT_PTE pd = (PNPT_PTE)pdPage;

        for (ULONG i = 0; i < NPT_ENTRIES_PER_TABLE; i++) {
            ULONG64 physAddr2MB = baseAddr1GB + (ULONG64)i * NPT_LARGE_PAGE_SIZE;
            pd[i].AsUInt64 = 0;
            pd[i].Fields.Present = 1;
            pd[i].Fields.ReadWrite = 1;
            pd[i].Fields.User = 1;
            pd[i].Fields.Accessed = 1;
            pd[i].Fields.Dirty = 1;
            pd[i].Fields.PageSize = 1;
            pd[i].Fields.PageFrameNumber = physAddr2MB >> 12;
        }

        {
            NPT_PTE newEntry;
            newEntry.AsUInt64 = 0;
            newEntry.Fields.Present = 1;
            newEntry.Fields.ReadWrite = 1;
            newEntry.Fields.User = 1;
            newEntry.Fields.Accessed = 1;
            newEntry.Fields.PageFrameNumber = pdPhysical.QuadPart >> 12;

            pdpt[pdptIndex].AsUInt64 = newEntry.AsUInt64;
        }
    }

    ULONG64 pdPhysAddr = pdpt[pdptIndex].Fields.PageFrameNumber << 12;
    PHYSICAL_ADDRESS pdPhys;
    pdPhys.QuadPart = pdPhysAddr;
    PNPT_PTE pd = (PNPT_PTE)MmGetVirtualForPhysical(pdPhys);
    if (!pd) {
        return FALSE;
    }

    if (pd[pdIndex].Fields.PageSize) {

        ULONG64 baseAddr2MB = pd[pdIndex].Fields.PageFrameNumber << 12;

        PHYSICAL_ADDRESS ptPhysical;
        PVOID ptPage = NptAllocateFromPool(&ptPhysical);
        if (!ptPage) {
            return FALSE;
        }

        PNPT_PTE pt = (PNPT_PTE)ptPage;

        for (ULONG i = 0; i < NPT_ENTRIES_PER_TABLE; i++) {
            ULONG64 physAddr4KB = baseAddr2MB + (ULONG64)i * NPT_PAGE_SIZE;
            pt[i].AsUInt64 = 0;
            pt[i].Fields.Present = 1;
            pt[i].Fields.ReadWrite = 1;
            pt[i].Fields.User = 1;
            pt[i].Fields.Accessed = 1;
            pt[i].Fields.Dirty = 1;
            pt[i].Fields.PageFrameNumber = physAddr4KB >> 12;

        }

        {
            NPT_PTE newEntry;
            newEntry.AsUInt64 = 0;
            newEntry.Fields.Present = 1;
            newEntry.Fields.ReadWrite = 1;
            newEntry.Fields.User = 1;
            newEntry.Fields.Accessed = 1;
            newEntry.Fields.PageFrameNumber = ptPhysical.QuadPart >> 12;

            pd[pdIndex].AsUInt64 = newEntry.AsUInt64;
        }
    }

    ULONG64 ptPhysAddr = pd[pdIndex].Fields.PageFrameNumber << 12;
    PHYSICAL_ADDRESS ptPhys;
    ptPhys.QuadPart = ptPhysAddr;
    PNPT_PTE pt = (PNPT_PTE)MmGetVirtualForPhysical(ptPhys);
    if (!pt) {
        return FALSE;
    }

    ULONG decoyIndex = (ULONG)((TargetHpa >> 12) % 4);

    pt[ptIndex].Fields.PageFrameNumber = hvState->decoyPagesPhysical[decoyIndex].QuadPart >> 12;

    pt[ptIndex].Fields.NoExecute = 1;

    pt[ptIndex].Fields.ReadWrite = 1;

    return TRUE;
}
