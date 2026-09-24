#include "hv_comm.h"
#include "platform/amd/svm.h"

static BOOLEAN HvIsPhysicalRam(ULONG64 physAddr) {
    if (!g_Hv.physMemRanges) return FALSE;

    if (physAddr > 0x0000010000000000ULL) return FALSE;

    for (ULONG i = 0; g_Hv.physMemRanges[i].NumberOfBytes.QuadPart != 0; i++) {
        ULONG64 base = g_Hv.physMemRanges[i].BaseAddress.QuadPart;
        ULONG64 size = g_Hv.physMemRanges[i].NumberOfBytes.QuadPart;

        if (physAddr >= base && physAddr < (base + size)) {
            return TRUE;
        }
    }
    return FALSE;
}

static __forceinline BOOLEAN HvQuickPhysCheck(ULONG64 physAddr) {
    if (!physAddr) return FALSE;
    if (physAddr > 0x0000010000000000ULL) return FALSE;
    if (physAddr & 0xFFF) return FALSE;
    return TRUE;
}

static BOOLEAN HvSafeRead64Physical(ULONG64 physAddr, PULONG64 outValue) {

    if (!HvIsPhysicalRam(physAddr)) return FALSE;

    ULONG core = KeGetCurrentProcessorNumber();
    PULONG64 pte = g_Hv.perCpu[core].scratchPte1;
    PVOID page = g_Hv.perCpu[core].scratchVa1;

    if (!pte || !page) return FALSE;

    *pte = 0x63ULL | (physAddr & 0x000FFFFFFFFFF000ULL);
    __invlpg(page);

    *outValue = *(PULONG64)((PUCHAR)page + (physAddr & 0xFFF));

    *pte = 0;
    __invlpg(page);
    return TRUE;
}

static ULONG64 HvExtractPtePhysical(ULONG64 pte) {
    if (pte & 1) return pte & 0x000FFFFFFFFFF000ULL;
    if (pte & (1ULL << 11)) return pte & 0x000FFFFFFFFFF000ULL;
    return 0;
}

ULONG64 HvTranslateGuestVa(ULONG64 processCr3, ULONG64 guestVa) {
    PHYSICAL_ADDRESS pa;
    ULONG64 entry;
    ULONG64 nextBase;

    ULONG pml4Idx = (ULONG)((guestVa >> 39) & 0x1FF);
    ULONG pdptIdx = (ULONG)((guestVa >> 30) & 0x1FF);
    ULONG pdIdx   = (ULONG)((guestVa >> 21) & 0x1FF);
    ULONG ptIdx   = (ULONG)((guestVa >> 12) & 0x1FF);

    ULONG64 pml4Base = processCr3 & 0x000FFFFFFFFFF000ULL;
    if (!HvIsPhysicalRam(pml4Base)) return 0;
    pa.QuadPart = pml4Base + (ULONG64)pml4Idx * 8;
    if (!HvSafeRead64Physical(pa.QuadPart, &entry)) return 0;

    if (!(entry & 1)) return 0;

    nextBase = entry & 0x000FFFFFFFFFF000ULL;
    if (!HvQuickPhysCheck(nextBase)) return 0;
    pa.QuadPart = nextBase + (ULONG64)pdptIdx * 8;
    if (!HvSafeRead64Physical(pa.QuadPart, &entry)) return 0;
    if (!(entry & 1)) return 0;

    if (entry & (1ULL << 7)) {
        ULONG64 pageBase = entry & 0x000FFFFFC0000000ULL;
        if (!HvIsPhysicalRam(pageBase)) return 0;
        return pageBase | (guestVa & 0x3FFFFFFFULL);
    }

    nextBase = entry & 0x000FFFFFFFFFF000ULL;
    if (!HvQuickPhysCheck(nextBase)) return 0;
    pa.QuadPart = nextBase + (ULONG64)pdIdx * 8;
    if (!HvSafeRead64Physical(pa.QuadPart, &entry)) return 0;

    if (entry & (1ULL << 7)) {

        ULONG64 pageBase = HvExtractPtePhysical(entry);
        if (!pageBase) return 0;

        pageBase &= 0x000FFFFFFFE00000ULL;
        if (!HvIsPhysicalRam(pageBase)) return 0;
        return pageBase | (guestVa & 0x1FFFFFULL);
    }
    if (!(entry & 1)) return 0;

    nextBase = entry & 0x000FFFFFFFFFF000ULL;
    if (!HvQuickPhysCheck(nextBase)) return 0;
    pa.QuadPart = nextBase + (ULONG64)ptIdx * 8;
    if (!HvSafeRead64Physical(pa.QuadPart, &entry)) return 0;

    {
        ULONG64 pageBase = HvExtractPtePhysical(entry);
        if (!pageBase) return 0;
        if (!HvIsPhysicalRam(pageBase)) return 0;
        return pageBase | (guestVa & 0xFFFULL);
    }
}

static BOOLEAN HvCopyPhysical(ULONG64 srcPa, ULONG64 dstPa, ULONG64 size) {
    if (!HvIsPhysicalRam(srcPa) || !HvIsPhysicalRam(dstPa)) return FALSE;

    ULONG core = KeGetCurrentProcessorNumber();
    PULONG64 pte1 = g_Hv.perCpu[core].scratchPte1;
    PULONG64 pte2 = g_Hv.perCpu[core].scratchPte2;
    PVOID page1 = g_Hv.perCpu[core].scratchVa1;
    PVOID page2 = g_Hv.perCpu[core].scratchVa2;

    if (!pte1 || !pte2 || !page1 || !page2) return FALSE;

    while (size > 0) {
        ULONG64 srcRemain, dstRemain, chunk;
        PUCHAR srcVa, dstVa;

        *pte1 = 0x63ULL | (srcPa & 0x000FFFFFFFFFF000ULL);
        *pte2 = 0x63ULL | (dstPa & 0x000FFFFFFFFFF000ULL);
        __invlpg(page1);
        __invlpg(page2);

        srcVa = (PUCHAR)page1 + (srcPa & 0xFFF);
        dstVa = (PUCHAR)page2 + (dstPa & 0xFFF);
        srcRemain = 0x1000 - (srcPa & 0xFFF);
        dstRemain = 0x1000 - (dstPa & 0xFFF);
        chunk = size;
        if (chunk > srcRemain) chunk = srcRemain;
        if (chunk > dstRemain) chunk = dstRemain;

        RtlCopyMemory(dstVa, srcVa, (SIZE_T)chunk);

        *pte1 = 0;
        *pte2 = 0;
        __invlpg(page1);
        __invlpg(page2);

        srcPa += chunk;
        dstPa += chunk;
        size -= chunk;
    }
    return TRUE;
}

BOOLEAN HvReadVirtualMemory(ULONG64 targetCr3, ULONG64 sourceVa,
                             ULONG64 callerCr3, ULONG64 destVa,
                             ULONG64 size) {

    if (size == 0 || size > 0x4000000) return FALSE;

    while (size > 0) {

        ULONG64 srcPa = HvTranslateGuestVa(targetCr3, sourceVa);
        if (!srcPa) return FALSE;

        ULONG64 dstPa = HvTranslateGuestVa(callerCr3, destVa);
        if (!dstPa) return FALSE;

        ULONG64 srcRemain = 0x1000 - (srcPa & 0xFFF);
        ULONG64 dstRemain = 0x1000 - (dstPa & 0xFFF);
        ULONG64 chunk = size;
        if (chunk > srcRemain) chunk = srcRemain;
        if (chunk > dstRemain) chunk = dstRemain;

        if (!HvCopyPhysical(srcPa, dstPa, chunk))
            return FALSE;

        sourceVa += chunk;
        destVa += chunk;
        size -= chunk;
    }
    return TRUE;
}

BOOLEAN HvWriteVirtualMemory(ULONG64 targetCr3, ULONG64 destVa,
                              ULONG64 callerCr3, ULONG64 sourceVa,
                              ULONG64 size) {

    if (size == 0 || size > 0x4000000) return FALSE;

    while (size > 0) {

        ULONG64 srcPa = HvTranslateGuestVa(callerCr3, sourceVa);
        if (!srcPa) return FALSE;

        ULONG64 dstPa = HvTranslateGuestVa(targetCr3, destVa);
        if (!dstPa) return FALSE;

        ULONG64 srcRemain = 0x1000 - (srcPa & 0xFFF);
        ULONG64 dstRemain = 0x1000 - (dstPa & 0xFFF);
        ULONG64 chunk = size;
        if (chunk > srcRemain) chunk = srcRemain;
        if (chunk > dstRemain) chunk = dstRemain;

        if (!HvCopyPhysical(srcPa, dstPa, chunk))
            return FALSE;

        sourceVa += chunk;
        destVa += chunk;
        size -= chunk;
    }
    return TRUE;
}

static BOOLEAN HvSafeReadSystemVa64(ULONG64 systemVa, PULONG64 outValue) {
    ULONG64 pa = HvTranslateGuestVa(__readcr3(), systemVa);
    if (!pa) return FALSE;
    return HvSafeRead64Physical(pa, outValue);
}

static ULONG64 HvFindProcessCr3(ULONG64 targetPid) {
    if (!g_Hv.systemEprocess || !g_Hv.eprocessLinksOffset) return 0;

    ULONG64 systemProc = (ULONG64)g_Hv.systemEprocess;
    ULONG64 head = systemProc + g_Hv.eprocessLinksOffset;
    ULONG64 current = 0;

    if (!HvSafeReadSystemVa64(head, &current)) return 0;
    if (current < 0xFFFF800000000000ULL) return 0;

    for (ULONG i = 0; i < 4096 && current != head; i++) {
        if (current < 0xFFFF800000000000ULL) return 0;

        ULONG64 eprocess = current - g_Hv.eprocessLinksOffset;
        ULONG64 pid = 0;

        if (!HvSafeReadSystemVa64(eprocess + g_Hv.eprocessPidOffset, &pid)) break;

        if (pid == targetPid) {
            ULONG64 dtb = 0;
            if (HvSafeReadSystemVa64(eprocess + g_Hv.eprocessDirTableOffset, &dtb)) {
                return dtb & 0x000FFFFFFFFFF000ULL;
            }
            return 0;
        }

        if (!HvSafeReadSystemVa64(current, &current)) break;
    }

    return 0;
}

static BOOLEAN HvIsUserCr3(ULONG64 candidateCr3) {
    ULONG64 pml4Pa = candidateCr3 & 0x000FFFFFFFFFF000ULL;
    if (!pml4Pa) return FALSE;
    if (!HvIsPhysicalRam(pml4Pa)) return FALSE;

    ULONG kernelEntries = 0;
    for (ULONG i = 256; i < 512; i++) {
        ULONG64 entry = 0;
        if (HvSafeRead64Physical(pml4Pa + (i * 8), &entry)) {
            if (entry & 1) {
                kernelEntries++;
            }
        }
    }

    return (kernelEntries > 0 && kernelEntries < 12);
}

static BOOLEAN HvVerifyUserCr3(ULONG64 candidateCr3, ULONG64 sectionBase, ULONG64 pebBase) {
    if (!candidateCr3 || !HvIsPhysicalRam(candidateCr3)) return FALSE;

    if (sectionBase) {
        ULONG64 translatedSectionPa = HvTranslateGuestVa(candidateCr3, sectionBase);
        if (translatedSectionPa) {
            ULONG64 magic = 0;
            if (HvSafeRead64Physical(translatedSectionPa, &magic) && (magic & 0xFFFF) == 0x5A4D) {
                return TRUE;
            }
        }
    }

    else if (pebBase) {
        ULONG64 translatedPebPa = HvTranslateGuestVa(candidateCr3, pebBase);
        if (translatedPebPa && HvIsUserCr3(candidateCr3)) {
            return TRUE;
        }
    }

    return FALSE;
}

static ULONG64 HvGetProcessBaseAddress(ULONG64 targetCr3) {
    if (!targetCr3) return 0;

    #define PEB_LDR_OFFSET       0x18
    #define LDR_IN_LOAD_OFFSET   0x10
    #define LDR_ENTRY_DLLBASE    0x30

    if (!g_Hv.targetPid || !g_Hv.systemEprocess || !g_Hv.eprocessLinksOffset) return 0;

    ULONG64 systemProc = (ULONG64)g_Hv.systemEprocess;
    ULONG64 head = systemProc + g_Hv.eprocessLinksOffset;
    ULONG64 current = 0;

    if (!HvSafeReadSystemVa64(head, &current)) return 0;
    if (current < 0xFFFF800000000000ULL) return 0;

    ULONG64 targetEprocess = 0;
    for (ULONG i = 0; i < 4096 && current != head; i++) {
        if (current < 0xFFFF800000000000ULL) break;
        ULONG64 eprocess = current - g_Hv.eprocessLinksOffset;
        ULONG64 pid = 0;
        if (!HvSafeReadSystemVa64(eprocess + g_Hv.eprocessPidOffset, &pid)) break;
        if (pid == g_Hv.targetPid) {
            targetEprocess = eprocess;
            break;
        }
        if (!HvSafeReadSystemVa64(current, &current)) break;
    }

    if (!targetEprocess) return 0xE1;

    if (g_Hv.eprocessSectionBaseOffset) {
        ULONG64 sectionBase = 0;
        HvSafeReadSystemVa64(targetEprocess + g_Hv.eprocessSectionBaseOffset, &sectionBase);

        if (sectionBase > 0x10000 && sectionBase < 0x800000000000ULL) {

            ULONG64 pebAddr = 0;
            HvSafeReadSystemVa64(targetEprocess + g_Hv.eprocessPebOffset, &pebAddr);

            ULONG64 freshCr3 = 0;
            HvSafeReadSystemVa64(targetEprocess + g_Hv.eprocessDirTableOffset, &freshCr3);
            freshCr3 &= 0x000FFFFFFFFFF000ULL;
            if (freshCr3) g_Hv.targetCr3 = freshCr3;

            if (pebAddr) {
                ULONG64 pebPa = HvTranslateGuestVa(g_Hv.targetCr3, pebAddr);
                if (pebPa) {

                    g_Hv.targetUserCr3 = g_Hv.targetCr3;
                } else {

                    BOOLEAN found = FALSE;

                    {
                        ULONG64 userDtb = 0;
                        HvSafeReadSystemVa64(targetEprocess + g_Hv.eprocessDirTableOffset + 8, &userDtb);
                        ULONG64 userDtbBase = userDtb & 0x000FFFFFFFFFF000ULL;
                        if (userDtbBase > 0x100000 && userDtbBase != g_Hv.targetCr3 &&
                            HvVerifyUserCr3(userDtbBase, sectionBase, pebAddr)) {
                            g_Hv.targetUserCr3 = userDtbBase;
                            found = TRUE;
                        }
                    }

                    if (!found) {
                        ULONG64 kptiOffsets[] = {
                            0x280, 0x388, 0x330, 0x158, 0x278,
                            0x400, 0x408, 0x410, 0x418, 0x420,
                            0x468, 0x470, 0x478, 0x480, 0x488,
                            0x578, 0x580, 0x588, 0x590, 0x598, 0x5A0
                        };
                        for (ULONG ki = 0; ki < sizeof(kptiOffsets)/sizeof(kptiOffsets[0]); ki++) {
                            ULONG64 optCr3 = 0;
                            HvSafeReadSystemVa64(targetEprocess + kptiOffsets[ki], &optCr3);
                            ULONG64 optCr3Base = optCr3 & 0x000FFFFFFFFFF000ULL;
                            if (optCr3Base > 0x100000 && optCr3Base != g_Hv.targetCr3 &&
                                HvVerifyUserCr3(optCr3Base, sectionBase, pebAddr)) {
                                g_Hv.targetUserCr3 = optCr3Base;
                                found = TRUE;
                                break;
                            }
                        }
                    }

                    if (!found) {
                        ULONG64 targetKernelPml4Pa = g_Hv.targetCr3 & 0x000FFFFFFFFFF000ULL;
                        ULONG64 scanStartPa = g_Hv.lastCr3ScanPa;

                        ULONG64 scanEndLimitPa = scanStartPa + (8ULL * 1024 * 1024);

                        BOOLEAN chunkFinished = FALSE;

                        for (ULONG r = 0; g_Hv.physMemRanges[r].NumberOfBytes.QuadPart != 0 && !found && !chunkFinished; r++) {
                            ULONG64 rStart = g_Hv.physMemRanges[r].BaseAddress.QuadPart & 0x000FFFFFFFFFF000ULL;
                            ULONG64 rEnd = (g_Hv.physMemRanges[r].BaseAddress.QuadPart + g_Hv.physMemRanges[r].NumberOfBytes.QuadPart) & 0x000FFFFFFFFFF000ULL;

                            if (rEnd <= scanStartPa) continue;
                            if (rStart < scanStartPa) rStart = scanStartPa;

                            for (ULONG64 testPa = rStart; testPa < rEnd; testPa += 0x1000) {
                                if (testPa >= scanEndLimitPa) {
                                    g_Hv.lastCr3ScanPa = testPa;
                                    chunkFinished = TRUE;
                                    break;
                                }

                                if (testPa == targetKernelPml4Pa) continue;

                                if (HvVerifyUserCr3(testPa, sectionBase, pebAddr)) {
                                    g_Hv.targetUserCr3 = testPa;
                                    found = TRUE;
                                    break;
                                }
                            }
                        }

                        if (!found) {
                            if (!chunkFinished) {

                                g_Hv.lastCr3ScanPa = 0;
                                g_Hv.cr3ScanSweepCount++;
                                g_Hv.targetUserCr3 = g_Hv.targetCr3;
                                found = TRUE;
                            } else {
                                return 2;
                            }
                        }
                    }

                    if (!found) g_Hv.targetUserCr3 = g_Hv.targetCr3;
                }
            } else {
                g_Hv.targetUserCr3 = g_Hv.targetCr3;
            }

            return sectionBase;
        }
    }

    ULONG64 pebAddr = 0;
    HvSafeReadSystemVa64(targetEprocess + g_Hv.eprocessPebOffset, &pebAddr);
    if (!pebAddr) return 0xE2;

    {
        ULONG64 freshCr3 = 0;
        HvSafeReadSystemVa64(targetEprocess + g_Hv.eprocessDirTableOffset, &freshCr3);
        if (freshCr3) targetCr3 = freshCr3;

        ULONG64 pebPa = HvTranslateGuestVa(targetCr3, pebAddr);
        if (!pebPa) {
            BOOLEAN foundUserCr3 = FALSE;

            ULONG64 kptiOffsets[] = { 0x280, 0x388, 0x330, 0x158, 0x278 };

            ULONG64 sectionBase = 0;
            if (g_Hv.eprocessSectionBaseOffset) HvSafeReadSystemVa64(targetEprocess + g_Hv.eprocessSectionBaseOffset, &sectionBase);

            for (ULONG i = 0; i < sizeof(kptiOffsets)/sizeof(kptiOffsets[0]); i++) {
                ULONG64 optCr3 = 0;
                HvSafeReadSystemVa64(targetEprocess + kptiOffsets[i], &optCr3);
                ULONG64 optCr3Base = optCr3 & 0x000FFFFFFFFFF000ULL;
                if (optCr3Base && optCr3Base != (targetCr3 & 0x000FFFFFFFFFF000ULL)) {
                    if (HvVerifyUserCr3(optCr3Base, sectionBase, pebAddr)) {
                        targetCr3 = optCr3Base;
                        g_Hv.targetUserCr3 = optCr3Base;
                        foundUserCr3 = TRUE;
                        break;
                    }
                }
            }

            if (!foundUserCr3) {
                for (ULONG offset = 0x28; offset < 0x600; offset += 8) {
                    if (offset == g_Hv.eprocessDirTableOffset) continue;
                    ULONG64 optCr3 = 0;
                    HvSafeReadSystemVa64(targetEprocess + offset, &optCr3);
                    ULONG64 optCr3Base = optCr3 & 0x000FFFFFFFFFF000ULL;
                    if (optCr3Base && optCr3Base != (targetCr3 & 0x000FFFFFFFFFF000ULL)) {
                        if (HvVerifyUserCr3(optCr3Base, sectionBase, pebAddr)) {
                            targetCr3 = optCr3Base;
                            g_Hv.targetUserCr3 = optCr3Base;
                            foundUserCr3 = TRUE;
                            break;
                        }
                    }
                }
            }

            if (!foundUserCr3) {
                g_Hv.targetUserCr3 = targetCr3;
            }
        } else {

            g_Hv.targetUserCr3 = targetCr3;
        }
    }

    {
        ULONG64 ldrPa, ldrAddr, firstEntryPa, firstEntry, dllBasePa, dllBase;

        ldrPa = HvTranslateGuestVa(targetCr3, pebAddr + PEB_LDR_OFFSET);
        if (!ldrPa) {
            ULONG64 pebPa2 = HvTranslateGuestVa(targetCr3, pebAddr);
            if (!pebPa2) return 0xE3;
            return 0xEB;
        }

        ldrAddr = 0;
        if (!HvSafeRead64Physical(ldrPa, &ldrAddr)) return 0xE4;
        if (!ldrAddr) return 0xE5;

        firstEntryPa = HvTranslateGuestVa(targetCr3, ldrAddr + LDR_IN_LOAD_OFFSET);
        if (!firstEntryPa) return 0xE6;

        firstEntry = 0;
        if (!HvSafeRead64Physical(firstEntryPa, &firstEntry)) return 0xE7;
        if (!firstEntry) return 0xE8;

        dllBasePa = HvTranslateGuestVa(targetCr3, firstEntry + LDR_ENTRY_DLLBASE);
        if (!dllBasePa) return 0xE9;

        dllBase = 0;
        if (!HvSafeRead64Physical(dllBasePa, &dllBase)) return 0xEA;

        return dllBase;
    }
}

ULONG64 HvCommDispatch(ULONG64 command, ULONG64 arg1, ULONG64 arg2,
                        ULONG64 arg3, ULONG64 guestCr3) {
    switch (command) {

    case HV_CMD_PING:
        return HV_STATUS_OK;

    case HV_CMD_ATTACH: {
        ULONG64 pid = arg1;
        ULONG64 cr3 = HvFindProcessCr3(pid);
        if (!cr3) return HV_STATUS_FAIL;

        g_Hv.targetCr3 = cr3;
        g_Hv.targetUserCr3 = 0;
        g_Hv.targetPid = pid;
        g_Hv.lastCr3ScanPa = 0;
        g_Hv.cr3ScanSweepCount = 0;
        return HV_STATUS_OK;
    }

    case HV_CMD_DETACH:
        g_Hv.targetCr3 = 0;
        g_Hv.targetUserCr3 = 0;
        g_Hv.targetPid = 0;
        return HV_STATUS_OK;

    case HV_CMD_READ: {
        if (!g_Hv.targetCr3) return HV_STATUS_NO_TARGET;

        ULONG64 srcVa = arg1;
        ULONG64 dstVa = arg2;
        ULONG64 size  = arg3;

        {
            static volatile LONG readCounter = 0;
            if ((InterlockedIncrement(&readCounter) & 0x1FFF) == 0) {
                ULONG64 freshCr3 = HvFindProcessCr3(g_Hv.targetPid);
                if (freshCr3) {
                    ULONG64 newCr3 = freshCr3 & 0x000FFFFFFFFFF000ULL;
                    if (newCr3 != g_Hv.targetCr3) {
                        g_Hv.targetCr3 = newCr3;

                        g_Hv.targetUserCr3 = 0;
                    }
                }
            }
        }

        ULONG64 readCr3 = (srcVa < 0x800000000000ULL && g_Hv.targetUserCr3)
                          ? g_Hv.targetUserCr3 : g_Hv.targetCr3;

        if (HvReadVirtualMemory(readCr3, srcVa, guestCr3, dstVa, size))
            return HV_STATUS_OK;
        return HV_STATUS_BAD_VA;
    }

    case HV_CMD_WRITE: {
        if (!g_Hv.targetCr3) return HV_STATUS_NO_TARGET;

        ULONG64 dstVa = arg1;
        ULONG64 srcVa = arg2;
        ULONG64 size  = arg3;

        {
            static volatile LONG writeCounter = 0;
            if ((InterlockedIncrement(&writeCounter) & 0x1FFF) == 0) {
                ULONG64 freshCr3 = HvFindProcessCr3(g_Hv.targetPid);
                if (freshCr3) {
                    ULONG64 newCr3 = freshCr3 & 0x000FFFFFFFFFF000ULL;
                    if (newCr3 != g_Hv.targetCr3) {
                        g_Hv.targetCr3 = newCr3;
                        g_Hv.targetUserCr3 = 0;
                    }
                }
            }
        }

        ULONG64 writeCr3 = (dstVa < 0x800000000000ULL && g_Hv.targetUserCr3)
                           ? g_Hv.targetUserCr3 : g_Hv.targetCr3;

        if (HvWriteVirtualMemory(writeCr3, dstVa, guestCr3, srcVa, size))
            return HV_STATUS_OK;
        return HV_STATUS_BAD_VA;
    }

    case HV_CMD_GET_BASE: {
        if (!g_Hv.targetCr3) return HV_STATUS_NO_TARGET;

        {
            ULONG64 freshCr3 = HvFindProcessCr3(g_Hv.targetPid);
            if (freshCr3) g_Hv.targetCr3 = freshCr3 & 0x000FFFFFFFFFF000ULL;
        }

        {
            ULONG64 base = HvGetProcessBaseAddress(g_Hv.targetCr3);
            if (base) return base;
        }
        return HV_STATUS_FAIL;
    }

    case HV_CMD_FIND_PROCESS: {
        if (!g_Hv.systemEprocess || !g_Hv.eprocessLinksOffset || !g_Hv.eprocessImageNameOffset) return 0;

        CHAR targetName[16];
        *(PULONG64)(&targetName[0]) = arg1;
        *(PULONG64)(&targetName[8]) = arg2;
        targetName[15] = '\0';

        ULONG64 systemProc = (ULONG64)g_Hv.systemEprocess;
        ULONG64 head = systemProc + g_Hv.eprocessLinksOffset;
        ULONG64 current = 0;

        if (!HvSafeReadSystemVa64(head, &current)) return 0;
        if (current < 0xFFFF800000000000ULL) return 0;

        for (ULONG i = 0; i < 4096 && current != head; i++) {
            if (current < 0xFFFF800000000000ULL) break;

            ULONG64 eprocess = current - g_Hv.eprocessLinksOffset;
            ULONG64 imageName1 = 0, imageName2 = 0;

            if (!HvSafeReadSystemVa64(eprocess + g_Hv.eprocessImageNameOffset, &imageName1)) break;
            HvSafeReadSystemVa64(eprocess + g_Hv.eprocessImageNameOffset + 8, &imageName2);

            CHAR imageName[16];
            *(PULONG64)(&imageName[0]) = imageName1;
            *(PULONG64)(&imageName[8]) = imageName2;
            imageName[15] = '\0';

            BOOLEAN match = TRUE;
            for (int j = 0; j < 15; j++) {
                CHAR c1 = targetName[j];
                CHAR c2 = imageName[j];
                if (c1 == 0 && c2 == 0) break;
                if (c1 >= 'A' && c1 <= 'Z') c1 += 32;
                if (c2 >= 'A' && c2 <= 'Z') c2 += 32;
                if (c1 != c2) {
                    match = FALSE;
                    break;
                }
                if (c1 == 0) break;
            }

            if (match) {
                ULONG64 pid = 0;
                if (HvSafeReadSystemVa64(eprocess + g_Hv.eprocessPidOffset, &pid)) {
                    return pid;
                }
                return 0;
            }

            if (!HvSafeReadSystemVa64(current, &current)) break;
        }
        return 0;
    }

    case HV_CMD_DIAG: {
        ULONG64 subCmd = arg1;
        UNREFERENCED_PARAMETER(arg2);

        switch (subCmd) {
        case 0: return g_Hv.targetCr3;
        case 1: return g_Hv.targetUserCr3;
        case 2: {
            ULONG64 pml4Base = g_Hv.targetCr3 & 0x000FFFFFFFFFF000ULL;
            ULONG64 entry = 0;
            if (!HvSafeRead64Physical(pml4Base, &entry)) return 0xDEAD0001;
            return entry;
        }
        case 3: return g_Hv.physMemRanges ? 1 : 0;
        case 4: {
            ULONG64 pml4Base = g_Hv.targetCr3 & 0x000FFFFFFFFFF000ULL;
            return HvIsPhysicalRam(pml4Base) ? pml4Base : 0xDEAD0002;
        }
        case 5: {
            ULONG core = KeGetCurrentProcessorNumber();
            if (!g_Hv.perCpu[core].scratchPte1) return 0xDEAD0003;
            if (!g_Hv.perCpu[core].scratchVa1) return 0xDEAD0004;
            return (ULONG64)g_Hv.perCpu[core].scratchVa1;
        }
        case 6: return g_Hv.eprocessSectionBaseOffset;
        case 7: return g_Hv.eprocessPebOffset;
        case 8: return g_Hv.scratchPml4Slot;
        case 9: {
            if (!g_Hv.targetPid) return 0xDEAD0009;
            ULONG64 eproc = 0;
            ULONG64 sys = (ULONG64)g_Hv.systemEprocess;
            ULONG64 head = sys + g_Hv.eprocessLinksOffset;
            ULONG64 cur = 0;
            if (!HvSafeReadSystemVa64(head, &cur)) return 0xDEAD000A;
            for (ULONG i = 0; i < 2048 && cur != head; i++) {
                ULONG64 ep = cur - g_Hv.eprocessLinksOffset;
                ULONG64 pid = 0;
                if (!HvSafeReadSystemVa64(ep + g_Hv.eprocessPidOffset, &pid)) break;
                if (pid == g_Hv.targetPid) { eproc = ep; break; }
                if (!HvSafeReadSystemVa64(cur, &cur)) break;
            }
            if (!eproc) return 0xDEAD000A;
            ULONG64 val = 0;
            HvSafeReadSystemVa64(eproc + 0x280, &val);
            return val;
        }
        case 10: {
            if (!g_Hv.targetPid) return 0xDEAD0009;
            ULONG64 eproc = 0;
            ULONG64 sys = (ULONG64)g_Hv.systemEprocess;
            ULONG64 head = sys + g_Hv.eprocessLinksOffset;
            ULONG64 cur = 0;
            if (!HvSafeReadSystemVa64(head, &cur)) return 0xDEAD000A;
            for (ULONG i = 0; i < 2048 && cur != head; i++) {
                ULONG64 ep = cur - g_Hv.eprocessLinksOffset;
                ULONG64 pid = 0;
                if (!HvSafeReadSystemVa64(ep + g_Hv.eprocessPidOffset, &pid)) break;
                if (pid == g_Hv.targetPid) { eproc = ep; break; }
                if (!HvSafeReadSystemVa64(cur, &cur)) break;
            }
            if (!eproc) return 0xDEAD000A;
            ULONG64 val = 0;
            HvSafeReadSystemVa64(eproc + g_Hv.eprocessDirTableOffset + 8, &val);
            return val;
        }
        case 11: {
            if (!g_Hv.targetPid) return 0xDEAD0009;
            ULONG64 eproc = 0;
            ULONG64 sys = (ULONG64)g_Hv.systemEprocess;
            ULONG64 head = sys + g_Hv.eprocessLinksOffset;
            ULONG64 cur = 0;
            if (!HvSafeReadSystemVa64(head, &cur)) return 0xDEAD000A;
            for (ULONG i = 0; i < 2048 && cur != head; i++) {
                ULONG64 ep = cur - g_Hv.eprocessLinksOffset;
                ULONG64 pid = 0;
                if (!HvSafeReadSystemVa64(ep + g_Hv.eprocessPidOffset, &pid)) break;
                if (pid == g_Hv.targetPid) { eproc = ep; break; }
                if (!HvSafeReadSystemVa64(cur, &cur)) break;
            }
            if (!eproc) return 0xDEAD000A;
            ULONG64 val = 0;
            HvSafeReadSystemVa64(eproc + g_Hv.eprocessDirTableOffset, &val);
            return val;
        }
        case 12: {
            if (!g_Hv.targetCr3 || !arg1) return 0xDEAD000B;
            return HvTranslateGuestVa(g_Hv.targetUserCr3, arg1);
        }
        case 13: {
            if (!g_Hv.targetPid) return 0xDEAD0009;
            ULONG64 eproc = 0;
            ULONG64 sys = (ULONG64)g_Hv.systemEprocess;
            ULONG64 head = sys + g_Hv.eprocessLinksOffset;
            ULONG64 cur = 0;
            if (!HvSafeReadSystemVa64(head, &cur)) return 0xDEAD000A;
            for (ULONG i = 0; i < 2048 && cur != head; i++) {
                ULONG64 ep = cur - g_Hv.eprocessLinksOffset;
                ULONG64 pid = 0;
                if (!HvSafeReadSystemVa64(ep + g_Hv.eprocessPidOffset, &pid)) break;
                if (pid == g_Hv.targetPid) { eproc = ep; break; }
                if (!HvSafeReadSystemVa64(cur, &cur)) break;
            }
            if (!eproc) return 0xDEAD000A;

            ULONG64 startIndex = arg1 ? arg1 : 0x28;
            ULONG64 sectionBase = 0;
            if (g_Hv.eprocessSectionBaseOffset) HvSafeReadSystemVa64(eproc + g_Hv.eprocessSectionBaseOffset, &sectionBase);
            ULONG64 pebBase = 0;
            HvSafeReadSystemVa64(eproc + g_Hv.eprocessPebOffset, &pebBase);
            if (!sectionBase && !pebBase) return 0;

            for (ULONG off = (ULONG)startIndex; off < 0xA00; off += 8) {
                if (off == g_Hv.eprocessDirTableOffset) continue;
                ULONG64 val = 0;
                if (!HvSafeReadSystemVa64(eproc + off, &val)) continue;
                ULONG64 pBase = val & 0x000FFFFFFFFFF000ULL;
                if (pBase > 0x100000 && pBase < 0x200000000000ULL && HvIsPhysicalRam(pBase)) {

                    if (sectionBase && HvTranslateGuestVa(pBase, sectionBase)) {
                        return ((ULONG64)off << 32) | (pBase >> 12);
                    }
                    if (pebBase && HvTranslateGuestVa(pBase, pebBase)) {
                        return ((ULONG64)off << 32) | (pBase >> 12);
                    }
                }
            }
            return 0;
        }
        case 14: {
            if (!g_Hv.targetPid || !g_Hv.systemEprocess || !g_Hv.eprocessLinksOffset) return 0;

            ULONG64 systemProc = (ULONG64)g_Hv.systemEprocess;
            ULONG64 head = systemProc + g_Hv.eprocessLinksOffset;
            ULONG64 current = 0;

            if (!HvSafeReadSystemVa64(head, &current)) return 0;
            if (current < 0xFFFF800000000000ULL) return 0;

            ULONG64 targetEprocess = 0;
            for (ULONG i = 0; i < 2048 && current != head; i++) {
                if (current < 0xFFFF800000000000ULL) break;
                ULONG64 eprocess = current - g_Hv.eprocessLinksOffset;
                ULONG64 pid = 0;
                if (!HvSafeReadSystemVa64(eprocess + g_Hv.eprocessPidOffset, &pid)) break;
                if (pid == g_Hv.targetPid) {
                    targetEprocess = eprocess;
                    break;
                }
                if (!HvSafeReadSystemVa64(current, &current)) break;
            }

            if (!targetEprocess) return 0;
            ULONG64 pebBase = 0;
            HvSafeReadSystemVa64(targetEprocess + g_Hv.eprocessPebOffset, &pebBase);
            return pebBase;
        }
        default: return 0xDEADFFFF;
        }
    }

    case HV_CMD_STEALTH_STATUS: {
        ULONG64 status = 0;
        ULONG core = KeGetCurrentProcessorNumber();
        PVMCB vmcb = (PVMCB)g_Hv.perCpu[core].guestVmcb;
        if (!vmcb) return 0;

        if (vmcb->ControlArea.InterceptMisc1 & (1u << 18))
            status |= STEALTH_CPUID_INTERCEPT;

        if (vmcb->ControlArea.InterceptMisc1 & (1u << 18))
            status |= STEALTH_HV_BIT_CLEARED;

        {
            int maxLeaf = g_Hv.cachedCpuid40000000[0];

            if (maxLeaf <= 0x40000010)
                status |= STEALTH_VENDOR_LEAF_CACHED;
        }

        if (vmcb->ControlArea.InterceptMisc1 & (1u << 18))
            status |= STEALTH_EXT_LEAVES_ZEROED;

        if (vmcb->ControlArea.InterceptMisc1 & (1u << 18))
            status |= STEALTH_SVM_LEAF_ZEROED;

        if (vmcb->ControlArea.InterceptMisc1 & (1u << 18))
            status |= STEALTH_80000008_MASKED;

        {
            ULONG64 realVmCr = __readmsr(0xC0010114);

            if (vmcb->ControlArea.InterceptMisc1 & (1u << 28))
                status |= STEALTH_VMCR_SVMDIS;
        }

        if (!(g_Hv.perCpu[core].guestEfer & EFER_SVME))
            status |= STEALTH_SHADOW_EFER_CLEAN;

        if (g_Hv.msrBitmap) {
            PUCHAR msrBmp = (PUCHAR)g_Hv.msrBitmap;

            if (msrBmp[2080] & 0x01)
                status |= STEALTH_EFER_RDMSR_BIT;

            if (msrBmp[2080] & 0x02)
                status |= STEALTH_EFER_WRMSR_BIT;

            if (msrBmp[4165] & 0x40)
                status |= STEALTH_HSAVE_RDMSR_BIT;

            if (msrBmp[4165] & 0x80)
                status |= STEALTH_HSAVE_WRMSR_BIT;

            if (msrBmp[4165] & 0x01)
                status |= STEALTH_VMCR_RDMSR_BIT;

            if (msrBmp[4165] & 0x02)
                status |= STEALTH_VMCR_WRMSR_BIT;
        }

        if (vmcb->ControlArea.MsrpmBasePa == g_Hv.msrBitmapPhysical.QuadPart)
            status |= STEALTH_MSRPM_BASE_VALID;

        if (vmcb->ControlArea.IopmBasePa != 0)
            status |= STEALTH_IOPM_CONFIGURED;

        if ((vmcb->ControlArea.InterceptMisc2 & 0x7F) == 0x7F)
            status |= STEALTH_SVM_INSNS_TRAPPED;

        if (vmcb->ControlArea.InterceptMisc2 & 0x02)
            status |= STEALTH_VMMCALL_TRAPPED;

        if (vmcb->ControlArea.InterceptMisc1 & (1u << 26))
            status |= STEALTH_INVLPGA_TRAPPED;

        if (vmcb->ControlArea.InterceptMisc1 & (1u << 31))
            status |= STEALTH_SHUTDOWN_INTERCEPT;

        if (vmcb->ControlArea.NestedCtl & 1)
            status |= STEALTH_NPT_ENABLED;

        if (vmcb->ControlArea.NCr3 == g_Hv.nptPml4Physical.QuadPart)
            status |= STEALTH_NPT_ROOT_VALID;

        {
            BOOLEAN allDecoys = TRUE;
            for (int i = 0; i < 4; i++) {
                if (g_Hv.decoyPagesPhysical[i].QuadPart == 0) {
                    allDecoys = FALSE;
                    break;
                }
            }
            if (allDecoys) status |= STEALTH_DECOYS_ALLOCATED;
        }

        if (g_Hv.decoyPages[0]) {
            PUCHAR d0 = (PUCHAR)g_Hv.decoyPages[0];
            BOOLEAN allZero = TRUE;
            for (int i = 0; i < 32; i++) {
                if (d0[i] != 0) { allZero = FALSE; break; }
            }
            if (allZero) status |= STEALTH_DECOY0_INTEGRITY;
        }

        if (g_Hv.driverImageBase != NULL && g_Hv.driverImageSize > 0)
            status |= STEALTH_DRIVER_IMAGE_TRACKED;

        if (g_Hv.trackedAllocCount > 0)
            status |= STEALTH_BIGPOOL_CLEANED;

        if (!g_Hv.iommuPresent || g_Hv.iommuEnabled)
            status |= STEALTH_IOMMU_CONSISTENT;

        if (g_Hv.commMagic != 0 && g_Hv.commMagic != g_Hv.bootstrapMagic)
            status |= STEALTH_ROLLING_MAGIC_VALID;

        if (InterlockedCompareExchange(&g_Hv.killSwitch, 0, 0) == 0)
            status |= STEALTH_KILL_SWITCH_OK;

        {
            BOOLEAN allLive = TRUE;
            for (ULONG i = 0; i < g_Hv.processorCount; i++) {
                if (!g_Hv.perCpu[i].virtualizationActive) {
                    allLive = FALSE;
                    break;
                }
            }
            if (allLive) status |= STEALTH_ALL_CORES_LIVE;
        }

        if (g_Hv.hostCr3 != NULL)
            status |= STEALTH_HOST_CR3_VALID;

        if (g_Hv.scratchPt && g_Hv.scratchPd && g_Hv.scratchPdpt)
            status |= STEALTH_SCRATCH_PT_VALID;

        if (g_Hv.eprocessPidOffset != 0 && g_Hv.eprocessLinksOffset != 0)
            status |= STEALTH_EPROCESS_OFFSETS_OK;

        if (g_Hv.physMemRanges != NULL)
            status |= STEALTH_PHYS_MEM_RANGES_OK;

        if (g_HvLogRing != NULL)
            status |= STEALTH_LOG_RING_ALIVE;

        if (vmcb->ControlArea.GuestAsid != 0)
            status |= STEALTH_GUEST_ASID_VALID;

        return status;
    }

    default:
        return HV_STATUS_BAD_CMD;
    }
}
