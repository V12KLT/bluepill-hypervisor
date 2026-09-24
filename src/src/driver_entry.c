#include "hv_platform.h"
#include "platform/amd/svm.h"
#include <ntimage.h>

PHV_STATE g_HvPtr = NULL;

static BOOLEAN HvAllocateGlobalState(void) {

    SIZE_T allocSize = (sizeof(HV_STATE) + PAGE_SIZE - 1) & ~(SIZE_T)(PAGE_SIZE - 1);
    PHYSICAL_ADDRESS maxAddr;
    maxAddr.QuadPart = 0xFFFFFFFFFFFFFFFFULL;
    PVOID block = MmAllocateContiguousMemory(allocSize, maxAddr);
    if (!block) return FALSE;
    RtlSecureZeroMemory(block, allocSize);
    g_HvPtr = (PHV_STATE)block;
    return TRUE;
}

static VOID HvFreeGlobalState(void) {
    if (g_HvPtr) {
        MmFreeContiguousMemory(g_HvPtr);
        g_HvPtr = NULL;
    }
}

VOID HvUnload(PDRIVER_OBJECT DriverObject) {
    UNREFERENCED_PARAMETER(DriverObject);

    if (!g_HvPtr) { LOG_OK("ForgeHV Unloaded (no state)."); HvLogFlush(); HvLogRingFree(); return; }

    if (g_Hv.vendor == CPU_VENDOR_AMD) {
        HvDevirtualizeAllCores();
    }

    LOG_INFO("Unloading ForgeHV...");
    HvLogFlush();

    HvFreePhase2();
    if (g_Hv.perCpu) {
        MmFreeContiguousMemory(g_Hv.perCpu);
        g_Hv.perCpu = NULL;
    }
    HvFreeGlobalState();
    LOG_OK("ForgeHV Unloaded.");
    HvLogFlush();
    HvLogRingFree();
}

#pragma section(".logstr$A", read)
__declspec(allocate(".logstr$A")) static const char g_LogStrStart = 0;

#pragma section(".logstr$Z", read)
__declspec(allocate(".logstr$Z")) static const char g_LogStrEnd = 0;

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {

    if (!HvAllocateGlobalState()) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    HvLogRingInit();

    UNREFERENCED_PARAMETER(RegistryPath);

    if (DriverObject != NULL) {
        DriverObject->DriverUnload = HvUnload;
    }

    LOG_INFO("========================================");
    LOG_INFO("ForgeHV - Ring -1 Initialization Phase 1");
    LOG_INFO("========================================");

    if (g_Hv.driverImageBase && g_Hv.driverImageSize) {
        LOG_OK("Mapper injected driver bounds: base=0x%p size=0x%X",
               g_Hv.driverImageBase, g_Hv.driverImageSize);
    }

    {

        PUCHAR scanAddr = (PUCHAR)((ULONG64)DriverEntry & ~0xFFFULL);
        BOOLEAN found = FALSE;
        for (ULONG attempt = 0; attempt < 0x400; attempt++) {

            if (!MmIsAddressValid(scanAddr)) {
                scanAddr -= 0x1000;
                continue;
            }
            if (scanAddr[0] == 'M' && scanAddr[1] == 'Z') {
                PIMAGE_DOS_HEADER dosHdr = (PIMAGE_DOS_HEADER)scanAddr;
                if (dosHdr->e_lfanew > 0 && dosHdr->e_lfanew < 0x1000) {
                    PUCHAR ntHdrAddr = scanAddr + dosHdr->e_lfanew;
                    if (MmIsAddressValid(ntHdrAddr) &&
                        MmIsAddressValid(ntHdrAddr + sizeof(IMAGE_NT_HEADERS64) - 1)) {
                        PIMAGE_NT_HEADERS64 ntHdr = (PIMAGE_NT_HEADERS64)ntHdrAddr;
                        if (ntHdr->Signature == IMAGE_NT_SIGNATURE &&
                            ntHdr->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
                            g_Hv.driverImageBase = (PVOID)scanAddr;
                            g_Hv.driverImageSize = ntHdr->OptionalHeader.SizeOfImage;
                            found = TRUE;
                            LOG_OK("Phase 0: Discovered own PE at 0x%p, size 0x%X",
                                   g_Hv.driverImageBase, g_Hv.driverImageSize);
                        }
                    }
                }
                if (found) break;
            }
            scanAddr -= 0x1000;
        }
        if (!found) {
            LOG_ERROR("Phase 0: Could not discover own PE image! SEH + self-cloaking unavailable.");
        }

        typedef struct _PDATA_ENTRY {
            ULONG BeginAddress;
            ULONG EndAddress;
            ULONG UnwindInfoAddress;
        } PDATA_ENTRY;

        if (g_Hv.driverImageBase && g_Hv.driverImageSize) {
            BOOLEAN hasPdata = FALSE;
            PIMAGE_DOS_HEADER dosHdr = (PIMAGE_DOS_HEADER)g_Hv.driverImageBase;
            PUCHAR ntHdrAddr = (PUCHAR)g_Hv.driverImageBase + dosHdr->e_lfanew;
            PIMAGE_NT_HEADERS64 ntHdr = (PIMAGE_NT_HEADERS64)ntHdrAddr;

            if (ntHdr->OptionalHeader.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_EXCEPTION) {
                IMAGE_DATA_DIRECTORY excDir =
                    ntHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
                if (excDir.VirtualAddress != 0 && excDir.Size >= sizeof(PDATA_ENTRY)) {
                    PDATA_ENTRY *pFunc = (PDATA_ENTRY *)((ULONG_PTR)g_Hv.driverImageBase + excDir.VirtualAddress);

                    if (MmIsAddressValid(pFunc) &&
                        MmIsAddressValid((PUCHAR)pFunc + sizeof(PDATA_ENTRY) - 1)) {
                        if (pFunc->BeginAddress != 0 &&
                            pFunc->EndAddress > pFunc->BeginAddress &&
                            pFunc->EndAddress < g_Hv.driverImageSize) {
                            hasPdata = TRUE;
                        }
                    }
                }
            }

            if (hasPdata) {
                typedef VOID (NTAPI *FN_RtlInsertInvertedFunctionTable)(
                    PVOID ImageBase, ULONG SizeOfImage);

                UNICODE_STRING fnName;
                RtlInitUnicodeString(&fnName, L"RtlInsertInvertedFunctionTable");
                FN_RtlInsertInvertedFunctionTable pfnInsert =
                    (FN_RtlInsertInvertedFunctionTable)MmGetSystemRoutineAddress(&fnName);

                if (pfnInsert) {

                    pfnInsert(g_Hv.driverImageBase, g_Hv.driverImageSize);
                    g_Hv.pdataRegistered = TRUE;
                    LOG_OK("Phase 0b: .pdata registered — __try/__except now functional.");
                } else {
                    LOG_ERROR("Phase 0b: RtlInsertInvertedFunctionTable not found — SEH unavailable.");
                }
            } else {
                LOG_ERROR("Phase 0b: No valid .pdata found — SEH registration skipped.");
                LOG_ERROR("Phase 0b: Ensure mapper copies PE header (destroyHeader=false).");
            }
        }
    }

    g_Hv.vendor = HvGetCpuVendor();
    if (g_Hv.vendor == CPU_VENDOR_AMD) {
        LOG_OK("Detected Target: AMD Processor");
    } else if (g_Hv.vendor == CPU_VENDOR_INTEL) {
        LOG_INFO("Detected Target: Intel Processor (Not supported yet)");
        return STATUS_NOT_SUPPORTED;
    } else {
        LOG_ERROR("Detected Target: Unknown Processor Context");
        return STATUS_NOT_SUPPORTED;
    }

    {
        int hvCpuInfo[4];
        __cpuid(hvCpuInfo, 1);
        BOOLEAN rootHvPresent = (hvCpuInfo[2] & (1u << 31)) != 0;

        ULONG64 efer = __readmsr(0xC0000080);
        ULONG64 vmHsave = 0;
        BOOLEAN vmHsaveOk = FALSE;

        if (!rootHvPresent) {
            __try {
                vmHsave = __readmsr(0xC0010117);
                vmHsaveOk = TRUE;
            } __except (EXCEPTION_EXECUTE_HANDLER) {
                vmHsaveOk = FALSE;
                LOG_INFO("VM_HSAVE_PA probe #GP — treating as clean and "
                         "letting SvmIsSupported produce the full diagnostic.");
            }
        } else {
            LOG_INFO("Root hypervisor present (CPUID HV-bit) — skipping "
                     "VM_HSAVE_PA probe. SvmIsSupported will bail cleanly.");
        }

        if (vmHsaveOk && (efer & (1ULL << 12)) && vmHsave != 0) {

            LOG_OK("Hypervisor already active (EFER.SVME=1, VM_HSAVE_PA=0x%llX). Skipping.", vmHsave);
            return STATUS_ALREADY_COMMITTED;
        }
    }

    LARGE_INTEGER interval;

    interval.QuadPart = -20000000LL;

    ULONG actualProcessorCount = KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS);
    g_Hv.processorCount = actualProcessorCount;
    LOG_INFO("Logical Processors Detected: %u", g_Hv.processorCount);

    SIZE_T perCpuActualSize = sizeof(PHV_PER_CPU) * g_Hv.processorCount;
    SIZE_T perCpuAllocSize  = (perCpuActualSize + PAGE_SIZE - 1) & ~(SIZE_T)(PAGE_SIZE - 1);
    PHYSICAL_ADDRESS maxAddr;
    maxAddr.QuadPart = 0xFFFFFFFFFFFFFFFFULL;
    g_Hv.perCpu = (PPHV_PER_CPU)MmAllocateContiguousMemory(perCpuAllocSize, maxAddr);
    if (!g_Hv.perCpu) {
        LOG_ERROR("Failed to allocate per-cpu state array!");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlSecureZeroMemory(g_Hv.perCpu, perCpuAllocSize);

    g_Hv.physMemRanges = MmGetPhysicalMemoryRanges();
    if (!g_Hv.physMemRanges) {
        LOG_ERROR("Failed to get physical memory ranges!");
        return STATUS_UNSUCCESSFUL;
    }
    LOG_INFO("Phase 1: Cached OS physical memory ranges.");

    {
        extern PEPROCESS PsInitialSystemProcess;
        g_Hv.systemEprocess = (PVOID)PsInitialSystemProcess;
        LOG_INFO("Phase 1: PsInitialSystemProcess cached at 0x%p", g_Hv.systemEprocess);
    }

    {
        PUCHAR proc = (PUCHAR)g_Hv.systemEprocess;
        g_Hv.eprocessDirTableOffset = 0x28;
        g_Hv.eprocessPidOffset = 0;

        for (ULONG off = 0x100; off < 0x700; off += 8) {
            if (*(PULONG64)(proc + off) != 4) continue;

            PLIST_ENTRY links = (PLIST_ENTRY)(proc + off + 8);
            ULONG64 flink = (ULONG64)links->Flink;
            ULONG64 blink = (ULONG64)links->Blink;

            if (flink < 0xFFFF800000000000ULL) continue;
            if (blink < 0xFFFF800000000000ULL) continue;

            if (flink == (ULONG64)links) continue;

            PLIST_ENTRY nextEntry = (PLIST_ENTRY)flink;
            if ((ULONG64)nextEntry->Blink != (ULONG64)links) continue;

            BOOLEAN walkOk = TRUE;
            PLIST_ENTRY walk = nextEntry;
            for (ULONG step = 0; step < 3; step++) {
                ULONG64 wf = (ULONG64)walk->Flink;
                if (wf < 0xFFFF800000000000ULL) { walkOk = FALSE; break; }
                walk = (PLIST_ENTRY)wf;
            }
            if (!walkOk) continue;

            g_Hv.eprocessPidOffset = off;
            g_Hv.eprocessLinksOffset = off + 8;
            break;
        }

        if (g_Hv.eprocessPidOffset == 0) {
            LOG_ERROR("Phase 1: EPROCESS PID offset discovery failed!");
            return STATUS_UNSUCCESSFUL;
        }

        g_Hv.eprocessImageNameOffset = 0;
        for (ULONG off = g_Hv.eprocessLinksOffset + 0x80; off < 0x900; off += 8) {
            if (RtlCompareMemory(proc + off, "System", 6) == 6) {
                g_Hv.eprocessImageNameOffset = off;
                break;
            }
        }

        g_Hv.eprocessPebOffset = 0;
        {
            typedef PVOID (NTAPI *FN_PsGetProcessPeb)(PEPROCESS Process);
            UNICODE_STRING fnName;
            RtlInitUnicodeString(&fnName, L"PsGetProcessPeb");
            FN_PsGetProcessPeb pfnGetPeb = (FN_PsGetProcessPeb)MmGetSystemRoutineAddress(&fnName);

            if (pfnGetPeb) {

                PLIST_ENTRY head = (PLIST_ENTRY)(proc + g_Hv.eprocessLinksOffset);
                PLIST_ENTRY cur = head->Flink;
                for (ULONG i = 0; i < 100 && cur != head; i++) {
                    PUCHAR eproc = (PUCHAR)cur - g_Hv.eprocessLinksOffset;
                    PVOID peb = pfnGetPeb((PEPROCESS)eproc);
                    if (peb) {

                        ULONG64 pebVal = (ULONG64)peb;
                        for (ULONG poff = g_Hv.eprocessLinksOffset + 0x80; poff < 0x700; poff += 8) {
                            if (*(PULONG64)(eproc + poff) == pebVal) {

                                if (*(PULONG64)(proc + poff) == 0) {
                                    g_Hv.eprocessPebOffset = poff;
                                    LOG_INFO("  PEB offset found via PsGetProcessPeb: 0x%X (PEB=0x%llx)", poff, pebVal);
                                    break;
                                }
                            }
                        }
                        if (g_Hv.eprocessPebOffset) break;
                    }
                    cur = cur->Flink;
                }
            }

            if (!g_Hv.eprocessPebOffset && g_Hv.eprocessImageNameOffset) {
                g_Hv.eprocessPebOffset = g_Hv.eprocessImageNameOffset - 0x58;
                LOG_INFO("  PEB offset derived from ImageFileName: 0x%X", g_Hv.eprocessPebOffset);
            }
        }

        g_Hv.eprocessSectionBaseOffset = 0;
        {
            typedef PVOID (NTAPI *FN_PsGetProcessSectionBaseAddress)(PEPROCESS Process);
            UNICODE_STRING fnName2;
            RtlInitUnicodeString(&fnName2, L"PsGetProcessSectionBaseAddress");
            FN_PsGetProcessSectionBaseAddress pfnGetSba =
                (FN_PsGetProcessSectionBaseAddress)MmGetSystemRoutineAddress(&fnName2);

            if (pfnGetSba) {
                PLIST_ENTRY head2 = (PLIST_ENTRY)(proc + g_Hv.eprocessLinksOffset);
                PLIST_ENTRY cur2 = head2->Flink;
                for (ULONG i = 0; i < 100 && cur2 != head2; i++) {
                    PUCHAR eproc = (PUCHAR)cur2 - g_Hv.eprocessLinksOffset;
                    PVOID sba = pfnGetSba((PEPROCESS)eproc);
                    if (sba && (ULONG64)sba > 0x10000 && (ULONG64)sba < 0x800000000000ULL) {
                        ULONG64 sbaVal = (ULONG64)sba;
                        for (ULONG soff = 0x200; soff < 0x700; soff += 8) {
                            if (*(PULONG64)(eproc + soff) == sbaVal) {

                                g_Hv.eprocessSectionBaseOffset = soff;
                                LOG_INFO("  SectionBaseAddress offset: 0x%X (val=0x%llx)", soff, sbaVal);
                                break;
                            }
                        }
                        if (g_Hv.eprocessSectionBaseOffset) break;
                    }
                    cur2 = cur2->Flink;
                }
            }
            if (!g_Hv.eprocessSectionBaseOffset) {
                LOG_INFO("  SectionBaseAddress offset not found (PEB walk fallback)");
            }
        }

        LOG_OK("Phase 1: EPROCESS offsets discovered for this build:");
        LOG_INFO("  UniqueProcessId:      0x%X", g_Hv.eprocessPidOffset);
        LOG_INFO("  ActiveProcessLinks:   0x%X", g_Hv.eprocessLinksOffset);
        LOG_INFO("  DirectoryTableBase:   0x%X", g_Hv.eprocessDirTableOffset);
        LOG_INFO("  ImageFileName:        0x%X", g_Hv.eprocessImageNameOffset);
        LOG_INFO("  PEB:                  0x%X", g_Hv.eprocessPebOffset);
        LOG_INFO("  SectionBaseAddress:   0x%X", g_Hv.eprocessSectionBaseOffset);
    }

    {
        PVOID ntosBase = NULL;

        if (RtlPcToFileHeader((PVOID)KeBugCheckEx, &ntosBase) != NULL) {
            PIMAGE_DOS_HEADER dosHdr = (PIMAGE_DOS_HEADER)ntosBase;
            if (dosHdr->e_magic == IMAGE_DOS_SIGNATURE) {
                PIMAGE_NT_HEADERS64 ntHdr = (PIMAGE_NT_HEADERS64)((PUCHAR)ntosBase + dosHdr->e_lfanew);
                if (ntHdr->Signature == IMAGE_NT_SIGNATURE) {
                    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(ntHdr);
                    for (ULONG i = 0; i < ntHdr->FileHeader.NumberOfSections; i++, section++) {
                        if (RtlCompareMemory(section->Name, ".text", 5) == 5) {
                            g_Hv.ntoskrnlTextBase = (ULONG64)ntosBase + section->VirtualAddress;
                            g_Hv.ntoskrnlTextSize = section->Misc.VirtualSize;
                            LOG_OK("Phase 1b: Found ntoskrnl .text at 0x%llx (size 0x%llx)",
                                   g_Hv.ntoskrnlTextBase, g_Hv.ntoskrnlTextSize);
                            break;
                        }
                    }
                }
            }
        }
        if (!g_Hv.ntoskrnlTextBase) {
            LOG_ERROR("Phase 1b: Failed to find ntoskrnl .text bounds. INVLPGA whitelisting degraded.");

            g_Hv.ntoskrnlTextBase = 0xFFFFF80000000000ULL;
            g_Hv.ntoskrnlTextSize = 0x1000000000ULL;
        }
    }

    if (g_Hv.vendor == CPU_VENDOR_AMD) {
        SvmSnapshotDispatcherHash();
        LOG_INFO("Phase 1: Exit-dispatcher hash captured: 0x%llX",
                 (unsigned long long)g_Hv.expectedDispatcherHash);
    }

    {
        ULONG64 mcgCap = __readmsr(0x179);
        g_Hv.mcBankCount = (ULONG)(mcgCap & 0xFF);
        LOG_INFO("Phase 1: MC bank count = %u (from MCG_CAP=0x%llX)",
                 g_Hv.mcBankCount, (unsigned long long)mcgCap);
    }

    LOG_INFO("Phase 1 Complete.");
    HvLogFlush();
    KeDelayExecutionThread(KernelMode, FALSE, &interval);

    if (!HvAllocatePhase2()) {
        LOG_ERROR("Phase 2 Allocation Failed!");
        HvLogFlush();
        HvFreePhase2();
        if (g_Hv.perCpu) {
            MmFreeContiguousMemory(g_Hv.perCpu);
            g_Hv.perCpu = NULL;
        }
        HvLogRingFree();
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    LOG_INFO("Phase 2 Complete.");
    HvLogFlush();
    KeDelayExecutionThread(KernelMode, FALSE, &interval);

    LOG_INFO("Phase 3 & 4: Subverting %u logical processors...", g_Hv.processorCount);
    HvLogFlush();

    ULONG subvertedCoreCount = 0;

    for (ULONG i = 0; i < g_Hv.processorCount; i++) {

        LOG_INFO("Core %u: Enabling SVM (EFER.SVME) and configuring VM_HSAVE_PA...", i);
        LOG_INFO("Core %u: Populating VMCB and enabling NPT (NCr3=0x%llx)...", i, g_Hv.nptPml4Physical.QuadPart);
        LOG_INFO("Core %u: Executing Subversion Phase 4 (VMRUN)...", i);

        KAFFINITY affinity = (KAFFINITY)(1ULL << i);
        KeSetSystemAffinityThread(affinity);

        KIRQL oldIrql = KeRaiseIrqlToDpcLevel();

        if (!HvInitializeVirtualizationPhase3()) {
            LOG_ERROR("Failed to init hardware virtualization on core %u!", i);
            KeLowerIrql(oldIrql);
            KeRevertToUserAffinityThread();
            HvLogFlush();

            if (subvertedCoreCount > 0) {
                LOG_INFO("Rolling back %u previously subverted core(s)...", subvertedCoreCount);
                HvDevirtualizeAllCores();
                HvLogFlush();
            }
            HvFreePhase2();
            HvLogRingFree();
            return STATUS_UNSUCCESSFUL;
        }

        if (!HvSubvertPhase4()) {
            LOG_ERROR("Failed to subvert core %u!", i);
            HvDisableVirtualizationPhase3();
            KeLowerIrql(oldIrql);
            KeRevertToUserAffinityThread();
            HvLogFlush();

            if (subvertedCoreCount > 0) {
                LOG_INFO("Rolling back %u previously subverted core(s)...", subvertedCoreCount);
                HvDevirtualizeAllCores();
                HvLogFlush();
            }
            HvFreePhase2();
            HvLogRingFree();
            return STATUS_UNSUCCESSFUL;
        }

        KeLowerIrql(oldIrql);
        KeRevertToUserAffinityThread();
        subvertedCoreCount++;

        LOG_OK("Logical Processor %u successfully subverted.", i);
    }
    HvLogFlush();

    {
        extern BOOLEAN NptHidePhysicalPageSafe(ULONG64 TargetHpa, PHV_STATE hvState);
        ULONG pagesHidden = 0;
        BOOLEAN hideOk = TRUE;

        LOG_INFO("Phase 4b: Hiding hypervisor memory via NPT remapping...");

        #define HIDE_ALLOC(va, sizeBytes) do { \
            if ((va) && hideOk) { \
                PHYSICAL_ADDRESS _pa = MmGetPhysicalAddress(va); \
                ULONG _pages = (ULONG)(((sizeBytes) + 0xFFF) >> 12); \
                for (ULONG _p = 0; _p < _pages; _p++) { \
                    if (!NptHidePhysicalPageSafe(_pa.QuadPart + (ULONG64)_p * 0x1000, g_HvPtr)) { \
                        LOG_ERROR("Phase 4b: Failed to hide PA 0x%llx", _pa.QuadPart + (ULONG64)_p * 0x1000); \
                        hideOk = FALSE; \
                        break; \
                    } \
                    pagesHidden++; \
                } \
            } \
        } while(0)

        HIDE_ALLOC(g_Hv.msrBitmap, 8192);
        HIDE_ALLOC(g_Hv.iopmBitmap, 12288);
        HIDE_ALLOC(g_Hv.hostCr3, 4096);
        HIDE_ALLOC(g_Hv.decoyPages[0], 4096);
        HIDE_ALLOC(g_Hv.decoyPages[1], 4096);
        HIDE_ALLOC(g_Hv.decoyPages[2], 4096);
        HIDE_ALLOC(g_Hv.decoyPages[3], 4096);

        HIDE_ALLOC(g_Hv.scratchPt, 4096);
        HIDE_ALLOC(g_Hv.scratchPd, 4096);
        HIDE_ALLOC(g_Hv.scratchPdpt, 4096);

        for (ULONG i = 0; i < g_Hv.processorCount && hideOk; i++) {
            HIDE_ALLOC(g_Hv.perCpu[i].hostSaveArea, 4096);
            HIDE_ALLOC(g_Hv.perCpu[i].guestVmcb, 4096);
            HIDE_ALLOC(g_Hv.perCpu[i].hostVmcb, 4096);
            HIDE_ALLOC(g_Hv.perCpu[i].hypervisorStack, 0x10000);
        }

        #undef HIDE_ALLOC

        if (hideOk) {

            LOG_OK("Phase 4b: Hidden %u control-structure pages from guest.", pagesHidden);
        } else {
            LOG_ERROR("Phase 4b: NPT hiding partially failed (%u pages hidden before error).", pagesHidden);
        }

        for (ULONG i = 0; i < g_Hv.processorCount; i++) {
            InterlockedExchange(&g_Hv.tlbFlushFlags[i], 1);
        }
        HvForceTlbFlushAllCores();
    }

    HvLogFlush();

    HvCleanBigPoolTrace();
    HvLogFlush();

    {
        extern BOOLEAN IommuEnable(void);
        extern BOOLEAN IommuHideHypervisorPages(void);

        __try {
            if (IommuEnable()) {
                IommuHideHypervisorPages();
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            LOG_ERROR("Phase 5: IOMMU initialization faulted (exception 0x%lx). DMA protection unavailable.", GetExceptionCode());
        }
    }

    LOG_OK("Phase 5 complete. All stealth layers active.");
    LOG_INFO("Forge AMD Hypervisor Initialization complete. All processors strictly virtualized.");
    HvLogFlush();

    {
        HV_STATE localHv          = *g_HvPtr;
        PVOID    driverBase       = localHv.driverImageBase;
        ULONG    driverSize       = localHv.driverImageSize;
        ULONG    procCount        = localHv.processorCount;
        PPHV_PER_CPU perCpuBase   = localHv.perCpu;

        #define HV_MAX_CORES_FOR_FLUSH 256
        volatile LONG* tlbFlushFlag[HV_MAX_CORES_FOR_FLUSH] = { 0 };
        ULONG flushCount = (procCount < HV_MAX_CORES_FOR_FLUSH) ? procCount : HV_MAX_CORES_FOR_FLUSH;
        for (ULONG i = 0; i < flushCount; i++) {
            tlbFlushFlag[i] = &localHv.tlbFlushFlags[i];
        }

        LOG_INFO("Phase 7: Cloaking perCpu memory...");
        LOG_INFO("Phase 7: Cloaking g_Hv structure...");
        LOG_INFO("Phase 7: Cloaking driver image (base=0x%p size=0x%x)", driverBase, driverSize);

        LARGE_INTEGER flushWait;
        flushWait.QuadPart = -20000000LL;
        KeDelayExecutionThread(KernelMode, FALSE, &flushWait);

        ULONG hidePartialFailures = 0;

        if (perCpuBase) {
            SIZE_T perCpuActualSize = sizeof(PHV_PER_CPU) * procCount;
            SIZE_T perCpuAllocSize  = (perCpuActualSize + PAGE_SIZE - 1) & ~(SIZE_T)(PAGE_SIZE - 1);
            ULONG numPages = (ULONG)(perCpuAllocSize / PAGE_SIZE);
            for (ULONG i = 0; i < numPages; i++) {
                ULONG64 va = (ULONG64)perCpuBase + (ULONG64)i * PAGE_SIZE;
                PHYSICAL_ADDRESS pa = MmGetPhysicalAddress((PVOID)va);
                if (pa.QuadPart != 0) {
                    if (!NptHidePhysicalPageSafe(pa.QuadPart, &localHv))
                        hidePartialFailures++;
                }
            }
        }

        if (g_HvPtr) {
            SIZE_T allocSize = (sizeof(HV_STATE) + PAGE_SIZE - 1) & ~(SIZE_T)(PAGE_SIZE - 1);
            ULONG numPages = (ULONG)(allocSize / PAGE_SIZE);
            for (ULONG i = 0; i < numPages; i++) {
                ULONG64 va = (ULONG64)g_HvPtr + (ULONG64)i * PAGE_SIZE;
                PHYSICAL_ADDRESS pa = MmGetPhysicalAddress((PVOID)va);
                if (pa.QuadPart != 0) {
                    if (!NptHidePhysicalPageSafe(pa.QuadPart, &localHv))
                        hidePartialFailures++;
                }
            }
        }

        if (driverBase && driverSize) {
            ULONG numPages = (driverSize + PAGE_SIZE - 1) / PAGE_SIZE;
            for (ULONG i = 0; i < numPages; i++) {
                ULONG64 va = (ULONG64)driverBase + (ULONG64)i * PAGE_SIZE;
#ifndef NDEBUG

                {
                    ULONG64 logstrStart = ((ULONG64)&g_LogStrStart) & ~(ULONG64)(PAGE_SIZE - 1);
                    ULONG64 logstrEnd   = ((ULONG64)&g_LogStrEnd + PAGE_SIZE - 1) & ~(ULONG64)(PAGE_SIZE - 1);
                    if (logstrEnd && va >= logstrStart && va < logstrEnd) continue;
                }
#endif
                PHYSICAL_ADDRESS pa = MmGetPhysicalAddress((PVOID)va);
                if (pa.QuadPart == 0) continue;
                if (!NptHidePhysicalPageSafe(pa.QuadPart, &localHv))
                    hidePartialFailures++;
            }
        }

        if (hidePartialFailures > 0) {
            g_Hv.stealthDegradedPageCount = hidePartialFailures;
            LOG_ERROR("Phase 7: %u pages left visible (split-pool exhausted). "
                      "Variant is stealth-degraded.",
                      hidePartialFailures);
        }

        for (ULONG i = 0; i < flushCount; i++) {
            if (tlbFlushFlag[i]) {
                InterlockedExchange(tlbFlushFlag[i], 1);
            }
        }
    }

    return STATUS_SUCCESS;
}
