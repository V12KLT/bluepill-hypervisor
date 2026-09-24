#include "hv_platform.h"
#include "hv_comm.h"
#include "platform/amd/npt.h"

PHV_LOG_RING g_HvLogRing = NULL;

BOOLEAN HvLogRingInit(void) {

    SIZE_T totalSize = sizeof(HV_LOG_RING) - 1 +
                       (SIZE_T)HV_LOG_RING_ENTRY_COUNT * HV_LOG_RING_ENTRY_SIZE;

    totalSize = (totalSize + PAGE_SIZE - 1) & ~(SIZE_T)(PAGE_SIZE - 1);

    g_HvLogRing = (PHV_LOG_RING)ExAllocatePoolWithTag(
        NonPagedPool, totalSize, 'gLvH');
    if (!g_HvLogRing) return FALSE;

    RtlSecureZeroMemory(g_HvLogRing, totalSize);
    g_HvLogRing->writeIndex = 0;
    g_HvLogRing->readIndex = 0;
    g_HvLogRing->capacity = HV_LOG_RING_ENTRY_COUNT;

    return TRUE;
}

VOID HvLogRingWrite(const char* formatted, int len) {
    if (!g_HvLogRing) return;

    LONG slot = InterlockedIncrement(&g_HvLogRing->writeIndex) - 1;
    LONG idx = slot % g_HvLogRing->capacity;

    LONG distance = slot - g_HvLogRing->readIndex;
    if (distance >= g_HvLogRing->capacity) {
        return;
    }

    CHAR* dest = &g_HvLogRing->buffer[idx * HV_LOG_RING_ENTRY_SIZE];
    int copyLen = len;
    if (copyLen >= HV_LOG_RING_ENTRY_SIZE)
        copyLen = HV_LOG_RING_ENTRY_SIZE - 1;

    RtlCopyMemory(dest, formatted, copyLen);
    dest[copyLen] = '\0';
}

VOID HvLogFlush(void) {
    if (!g_HvLogRing) return;

    LONG writeSnapshot = g_HvLogRing->writeIndex;
    LONG readIdx = g_HvLogRing->readIndex;

    while (readIdx < writeSnapshot) {
        LONG idx = readIdx % g_HvLogRing->capacity;
        CHAR* entry = &g_HvLogRing->buffer[idx * HV_LOG_RING_ENTRY_SIZE];

        if (entry[0] != '\0') {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "%s", entry);
            entry[0] = '\0';
        }

        readIdx++;
    }

    g_HvLogRing->readIndex = readIdx;
}

VOID HvLogRingFree(void) {
    if (g_HvLogRing) {

        HvLogFlush();
        ExFreePoolWithTag(g_HvLogRing, 'gLvH');
        g_HvLogRing = NULL;
    }
}

CPU_VENDOR HvGetCpuVendor(void) {
  int cpuInfo[4];
  __cpuid(cpuInfo, 0);

  if (cpuInfo[1] == 0x68747541 && cpuInfo[2] == 0x444D4163 &&
      cpuInfo[3] == 0x69746E65) {
    return CPU_VENDOR_AMD;
  }

  if (cpuInfo[1] == 0x756e6547 && cpuInfo[2] == 0x6c65746e &&
      cpuInfo[3] == 0x49656e69) {
    return CPU_VENDOR_INTEL;
  }

  return CPU_VENDOR_UNKNOWN;
}

PVOID HvAllocatePhysicalMemory(SIZE_T NumberOfBytes,
                               PPHYSICAL_ADDRESS OutPhysical) {
  PHYSICAL_ADDRESS lowest = {0};
  PHYSICAL_ADDRESS highest;
  highest.QuadPart =
      ~0ull;

  PVOID memory =
      MmAllocateContiguousMemorySpecifyCacheNode(NumberOfBytes, lowest, highest,
                                                 lowest,
                                                 MmCached, MM_ANY_NODE_OK);

  if (memory) {
    RtlSecureZeroMemory(memory, NumberOfBytes);
    *OutPhysical = MmGetPhysicalAddress(memory);

    if (g_Hv.trackedAllocCount < HV_MAX_TRACKED_ALLOCS) {
      g_Hv.trackedAllocs[g_Hv.trackedAllocCount++] = memory;
    }
  } else {
    OutPhysical->QuadPart = 0;
  }
  return memory;
}

VOID HvFreePhysicalMemory(PVOID VirtualAddress) {
  if (VirtualAddress) {
    MmFreeContiguousMemory(VirtualAddress);
  }
}

static PULONG64 HvFindPteVaForKernelVa(PVOID va) {
  ULONG64 cr3 = __readcr3() & 0x000FFFFFFFFFF000ULL;
  ULONG64 v = (ULONG64)va;
  PHYSICAL_ADDRESS pa;
  ULONG64 entry;

  pa.QuadPart = cr3 + ((v >> 39) & 0x1FF) * 8;
  PULONG64 ptr = (PULONG64)MmGetVirtualForPhysical(pa);
  if (!ptr)
    return NULL;
  entry = *ptr;
  if (!(entry & 1))
    return NULL;

  pa.QuadPart = (entry & 0x000FFFFFFFFFF000ULL) + ((v >> 30) & 0x1FF) * 8;
  ptr = (PULONG64)MmGetVirtualForPhysical(pa);
  if (!ptr)
    return NULL;
  entry = *ptr;
  if (!(entry & 1) || (entry & 0x80))
    return NULL;

  pa.QuadPart = (entry & 0x000FFFFFFFFFF000ULL) + ((v >> 21) & 0x1FF) * 8;
  ptr = (PULONG64)MmGetVirtualForPhysical(pa);
  if (!ptr)
    return NULL;
  entry = *ptr;
  if (!(entry & 1) || (entry & 0x80))
    return NULL;

  pa.QuadPart = (entry & 0x000FFFFFFFFFF000ULL) + ((v >> 12) & 0x1FF) * 8;
  return (PULONG64)MmGetVirtualForPhysical(pa);
}

BOOLEAN HvAllocatePhase2(void) {
  LOG_INFO("Phase 2: Allocating Hypervisor Shared Memory...");

  g_Hv.msrBitmap = HvAllocatePhysicalMemory(8192, &g_Hv.msrBitmapPhysical);
  if (!g_Hv.msrBitmap) {
    LOG_ERROR("Failed to allocate MSR Bitmap");
    return FALSE;
  }

  g_Hv.iopmBitmap = HvAllocatePhysicalMemory(12288, &g_Hv.iopmBitmapPhysical);
  if (!g_Hv.iopmBitmap) {
    LOG_ERROR("Failed to allocate IOPM Bitmap");
    return FALSE;
  }

  RtlSecureZeroMemory(g_Hv.msrBitmap, 8192);

  ((PUCHAR)g_Hv.msrBitmap)[2080] = 0x03;

  ((PUCHAR)g_Hv.msrBitmap)[4165] |=
      0xC0;

  ((PUCHAR)g_Hv.msrBitmap)[4165] |=
      0x03;

  RtlSecureZeroMemory(g_Hv.iopmBitmap, 12288);

  {
    ULONG bootId = SharedUserData->BootId;
    g_Hv.bootstrapMagic = HV_MAGIC_MIX(bootId);

    if (g_Hv.bootstrapMagic == 0 ||
        g_Hv.bootstrapMagic == 0x464F5247ULL)
      g_Hv.bootstrapMagic ^= 0xDEADCAFEULL;
    LOG_INFO("Bootstrap magic derived from BootId %u: 0x%llx", bootId,
             g_Hv.bootstrapMagic);
  }

  {
    ULONG64 tsc1 = __rdtsc();
    ULONG64 tsc2 = __rdtsc();
    ULONG64 seed = tsc1 ^ (tsc2 << 17) ^ ((ULONG64)(ULONG_PTR)&g_Hv << 3);

    while (seed == g_Hv.bootstrapMagic || seed == 0x464F5247ULL ||
           seed == 0)
      seed ^= __rdtsc();
    g_Hv.commMagic = seed;
  }

  {
    ULONG64 rotEntropy = __rdtsc() ^ (__rdtsc() << 11);
    g_Hv.cpuidSteppingRotation = (ULONG)(rotEntropy & 0xF);
    g_Hv.cpuidBrandRotation    = (UCHAR)((rotEntropy >> 4) & 0xFF);
  }

  for (int i = 0; i < 4; i++) {
    g_Hv.decoyPages[i] = HvAllocatePhysicalMemory(4096, &g_Hv.decoyPagesPhysical[i]);
    if (!g_Hv.decoyPages[i]) {
      LOG_ERROR("Failed to allocate decoy page %d", i);
      return FALSE;
    }

    PVOID remainderStart = (PUCHAR)g_Hv.decoyPages[i] + 32;
    SIZE_T remainderSize = 4096 - 32;

    switch (i) {
      case 0: RtlSecureZeroMemory(g_Hv.decoyPages[i], 4096); break;
      case 1: RtlFillMemory(remainderStart, remainderSize, 0xCD); break;
      case 2: RtlFillMemory(remainderStart, remainderSize, 0xDD); break;
      case 3: {

        ULONG64* qwords = (ULONG64*)remainderStart;
        for (SIZE_T j = 0; j < remainderSize / 8; j++) {
          qwords[j] = __rdtsc() ^ (g_Hv.commMagic << (j % 17));
        }
        break;
      }
    }

    RtlSecureZeroMemory(g_Hv.decoyPages[i], 32);
  }

  {
    int vgifInfo[4];
    __cpuid(vgifInfo, 0x8000000A);
    g_Hv.vgifSupported = (vgifInfo[3] & (1 << 16)) != 0;
    g_Hv.decodeAssistsSupported = (vgifInfo[3] & (1 << 7)) != 0;
    if (g_Hv.vgifSupported) {
      LOG_INFO("Phase 2: CPU supports Virtual GIF (VGIF).");
    }
    if (g_Hv.decodeAssistsSupported) {
      LOG_INFO("Phase 2: CPU supports DECODE_ASSISTS.");
    } else {
      LOG_INFO(
          "Phase 2: DECODE_ASSISTS not supported — DR interception disabled.");
    }
  }

  __cpuidex(g_Hv.cachedCpuid40000000, 0x40000000, 0);

  LOG_INFO("Phase 2: Building NPT identity map...");
  ULONG64 nptRoot = NptBuildIdentityMap();
  if (nptRoot == 0) {
    LOG_ERROR("Failed to build NPT identity map!");
    return FALSE;
  }

  if (!NptPreallocateSplitPages(NPT_SPLIT_POOL_MAX)) {
    LOG_ERROR("Failed to pre-allocate NPT split pages!");
    return FALSE;
  }

  PHYSICAL_ADDRESS dummyPa;
  g_Hv.tlbFlushFlags = HvAllocatePhysicalMemory(PAGE_SIZE, &dummyPa);
  if (!g_Hv.tlbFlushFlags) {
    LOG_ERROR("Failed to allocate TLB Flush Flags array!");
    return FALSE;
  }

  LOG_INFO(
      "Phase 2: Allocating Host/Guest VMCB, HSA states, and Host Stacks...");

  for (ULONG i = 0; i < g_Hv.processorCount; i++) {

    g_Hv.perCpu[i].hostSaveArea =
        HvAllocatePhysicalMemory(4096, &g_Hv.perCpu[i].hostSaveAreaPhysical);
    if (!g_Hv.perCpu[i].hostSaveArea) {
      LOG_ERROR("Failed to allocate HSA for core %u", i);
      return FALSE;
    }

    g_Hv.perCpu[i].guestVmcb =
        HvAllocatePhysicalMemory(4096, &g_Hv.perCpu[i].guestVmcbPhysical);
    if (!g_Hv.perCpu[i].guestVmcb) {
      LOG_ERROR("Failed to allocate Guest VMCB for core %u", i);
      return FALSE;
    }

    g_Hv.perCpu[i].hostVmcb =
        HvAllocatePhysicalMemory(4096, &g_Hv.perCpu[i].hostVmcbPhysical);
    if (!g_Hv.perCpu[i].hostVmcb) {
      LOG_ERROR("Failed to allocate Host VMCB for core %u", i);
      return FALSE;
    }

    {
      PHYSICAL_ADDRESS dummy;
      g_Hv.perCpu[i].hypervisorStack =
          HvAllocatePhysicalMemory(0x10000, &dummy);
      if (!g_Hv.perCpu[i].hypervisorStack) {
        LOG_ERROR("Failed to allocate Hypervisor Stack for core %u", i);
        return FALSE;
      }
    }
  }

  g_Hv.hostCr3 = HvAllocatePhysicalMemory(4096, &g_Hv.hostCr3Physical);
  if (!g_Hv.hostCr3) {
    LOG_ERROR("Failed to allocate Host CR3");
    return FALSE;
  }

  PULONG64 hostPml4 = (PULONG64)g_Hv.hostCr3;
  RtlSecureZeroMemory(hostPml4, 4096);

  PUCHAR sysProc = (PUCHAR)g_Hv.systemEprocess;
  ULONG64 sysCr3Raw = *(PULONG64)(sysProc + 0x28);
  PHYSICAL_ADDRESS sysCr3Pa;
  sysCr3Pa.QuadPart = sysCr3Raw & 0x000FFFFFFFFFF000ULL;
  PULONG64 sysPml4 = (PULONG64)MmGetVirtualForPhysical(sysCr3Pa);

  ULONG64 curCr3Raw = __readcr3();
  PHYSICAL_ADDRESS curCr3Pa;
  curCr3Pa.QuadPart = curCr3Raw & 0x000FFFFFFFFFF000ULL;
  PULONG64 curPml4 = (PULONG64)MmGetVirtualForPhysical(curCr3Pa);

  if (sysPml4 && curPml4) {

    for (ULONG k = 256; k < 512; k++) {
      hostPml4[k] = sysPml4[k];
      if (curPml4[k] && !hostPml4[k]) {
        hostPml4[k] = curPml4[k];
      }
    }

    for (ULONG k = 0; k < 256; k++) {
      g_Hv.systemCr3KernelSnapshot[k] = sysPml4[256 + k];
    }
    g_Hv.systemCr3SnapshotValid = TRUE;
  } else {
    LOG_ERROR("Failed to map PML4 for CR3 construction");
    return FALSE;
  }

  LOG_INFO("Phase 2: Merged Host CR3 constructed at 0x%llx",
           g_Hv.hostCr3Physical.QuadPart);

  {
    PHYSICAL_ADDRESS pdptPhys, pdPhys, ptPhys;
    PULONG64 pdptVa, pdVa, ptVa;
    ULONG slot = 0;
    ULONG64 scratchVaBase;

    g_Hv.scratchPdpt = HvAllocatePhysicalMemory(4096, &pdptPhys);
    g_Hv.scratchPd = HvAllocatePhysicalMemory(4096, &pdPhys);
    g_Hv.scratchPt = HvAllocatePhysicalMemory(4096, &ptPhys);
    if (!g_Hv.scratchPdpt || !g_Hv.scratchPd || !g_Hv.scratchPt) {
      LOG_ERROR("Failed to allocate scratch page table hierarchy");
      return FALSE;
    }

    pdptVa = (PULONG64)g_Hv.scratchPdpt;
    pdVa = (PULONG64)g_Hv.scratchPd;
    ptVa = (PULONG64)g_Hv.scratchPt;

    for (ULONG k = 511; k >= 256; k--) {
      if (hostPml4[k] == 0) {
        slot = k;
        break;
      }
    }
    if (slot == 0) {
      LOG_ERROR("No unused PML4 slot for scratch pages");
      return FALSE;
    }
    g_Hv.scratchPml4Slot = slot;

    hostPml4[slot] = pdptPhys.QuadPart | 0x63;
    pdptVa[0] = pdPhys.QuadPart | 0x63;
    pdVa[0] = ptPhys.QuadPart | 0x63;

    scratchVaBase = 0xFFFF000000000000ULL | ((ULONG64)slot << 39);

    for (ULONG i = 0; i < g_Hv.processorCount; i++) {
      ULONG ptIdx1 = 2 * i;
      ULONG ptIdx2 = 2 * i + 1;

      g_Hv.perCpu[i].scratchVa1 =
          (PVOID)(scratchVaBase + (ULONG64)ptIdx1 * 0x1000);
      g_Hv.perCpu[i].scratchVa2 =
          (PVOID)(scratchVaBase + (ULONG64)ptIdx2 * 0x1000);

      g_Hv.perCpu[i].scratchPte1 = &ptVa[ptIdx1];
      g_Hv.perCpu[i].scratchPte2 = &ptVa[ptIdx2];

      ptVa[ptIdx1] = 0;
      ptVa[ptIdx2] = 0;
    }

    LOG_INFO("Phase 2: Scratch PT at PML4[%u], base VA 0x%llx, %u cores", slot,
             scratchVaBase, g_Hv.processorCount);
  }

  LOG_OK("Memory dynamically tracked and 4KB-aligned successfully.");
  return TRUE;
}

VOID HvRefreshHostCr3(ULONG64 guestCr3) {
  if (!g_Hv.hostCr3)
    return;

  ULONG core = KeGetCurrentProcessorNumber();
  PULONG64 pte = g_Hv.perCpu[core].scratchPte1;
  PVOID page = g_Hv.perCpu[core].scratchVa1;

  if (!pte || !page)
    return;

  ULONG64 guestPml4Pa = guestCr3 & ~0xFFFULL;

  *pte = 0x63ULL | (guestPml4Pa & 0x000FFFFFFFFFF000ULL);
  __invlpg(page);

  PULONG64 guestPml4 = (PULONG64)page;
  PULONG64 hostPml4 = (PULONG64)g_Hv.hostCr3;
  ULONG scratchSlot = g_Hv.scratchPml4Slot;

  ULONG kernelEntries = 0;
  ULONG snapshotMatches = 0;
  const ULONG64 pdptMask = 0x000FFFFFFFFFF000ULL;
  for (ULONG k = 256; k < 512; k++) {
    ULONG64 e = guestPml4[k];
    if (e & 1) {
      kernelEntries++;
      if (g_Hv.systemCr3SnapshotValid) {
        ULONG64 snapEntry = g_Hv.systemCr3KernelSnapshot[k - 256];
        if ((snapEntry & 1) && ((e & pdptMask) == (snapEntry & pdptMask))) {
          snapshotMatches++;
        }
      }
    }
  }

  BOOLEAN isFullKernelCr3 = FALSE;
  if (g_Hv.systemCr3SnapshotValid) {

    isFullKernelCr3 = (snapshotMatches >= 32) || (kernelEntries > 128);
  } else {
    isFullKernelCr3 = (kernelEntries > 128);
  }

  if (isFullKernelCr3) {
    for (ULONG k = 256; k < 512; k++) {

      if (k == scratchSlot)
        continue;

      ULONG64 guestEntry = guestPml4[k];

      if (guestEntry & 1) {

        if (g_Hv.systemCr3SnapshotValid) {
          ULONG64 snapEntry = g_Hv.systemCr3KernelSnapshot[k - 256];
          if ((snapEntry & 1) &&
              ((guestEntry & pdptMask) != (snapEntry & pdptMask))) {
            continue;
          }
        }

        volatile LONG64 *slot = (volatile LONG64 *)&hostPml4[k];
        LONG64 current = (LONG64)hostPml4[k];
        if (current != (LONG64)guestEntry) {
          InterlockedCompareExchange64(slot, (LONG64)guestEntry, current);
        }
      }
    }
  }

  *pte = 0;
  __invlpg(page);
}

VOID HvGcStaleHostCr3Slots(ULONG64 guestCr3) {
  if (!g_Hv.hostCr3 || !g_Hv.systemCr3SnapshotValid)
    return;

  ULONG core = KeGetCurrentProcessorNumber();
  PULONG64 pte = g_Hv.perCpu[core].scratchPte1;
  PVOID page = g_Hv.perCpu[core].scratchVa1;
  if (!pte || !page)
    return;

  ULONG64 guestPml4Pa = guestCr3 & ~0xFFFULL;
  *pte = 0x63ULL | (guestPml4Pa & 0x000FFFFFFFFFF000ULL);
  __invlpg(page);

  PULONG64 guestPml4 = (PULONG64)page;
  PULONG64 hostPml4 = (PULONG64)g_Hv.hostCr3;
  ULONG scratchSlot = g_Hv.scratchPml4Slot;

  const ULONG64 pdptMask = 0x000FFFFFFFFFF000ULL;
  ULONG snapshotMatches = 0;
  for (ULONG k = 256; k < 512; k++) {
    ULONG64 e = guestPml4[k];
    if (e & 1) {
      ULONG64 snapEntry = g_Hv.systemCr3KernelSnapshot[k - 256];
      if ((snapEntry & 1) && ((e & pdptMask) == (snapEntry & pdptMask))) {
        snapshotMatches++;
      }
    }
  }

  if (snapshotMatches >= 32) {
    for (ULONG k = 256; k < 512; k++) {
      if (k == scratchSlot)
        continue;

      ULONG64 hostEntry = hostPml4[k];
      if (!(hostEntry & 1))
        continue;

      ULONG64 guestEntry = guestPml4[k];
      BOOLEAN guestHasEntry = (guestEntry & 1) != 0;
      BOOLEAN pdptDiffers = guestHasEntry &&
                            ((hostEntry & pdptMask) != (guestEntry & pdptMask));

      if (!guestHasEntry || pdptDiffers) {

        volatile LONG64 *slot = (volatile LONG64 *)&hostPml4[k];
        InterlockedCompareExchange64(slot, 0, (LONG64)hostEntry);
      }
    }
  }

  *pte = 0;
  __invlpg(page);
}

VOID HvFreePhase2(void) {

  extern VOID IommuCleanup(void);
  IommuCleanup();

  NptFree();

  if (g_Hv.msrBitmap) {
    HvFreePhysicalMemory(g_Hv.msrBitmap);
    g_Hv.msrBitmap = NULL;
  }

  if (g_Hv.iopmBitmap) {
    HvFreePhysicalMemory(g_Hv.iopmBitmap);
    g_Hv.iopmBitmap = NULL;
  }

  for (int i = 0; i < 4; i++) {
    if (g_Hv.decoyPages[i]) {
      HvFreePhysicalMemory(g_Hv.decoyPages[i]);
      g_Hv.decoyPages[i] = NULL;
    }
  }

  if (g_Hv.scratchPt) {
    HvFreePhysicalMemory(g_Hv.scratchPt);
    g_Hv.scratchPt = NULL;
  }
  if (g_Hv.scratchPd) {
    HvFreePhysicalMemory(g_Hv.scratchPd);
    g_Hv.scratchPd = NULL;
  }
  if (g_Hv.scratchPdpt) {
    HvFreePhysicalMemory(g_Hv.scratchPdpt);
    g_Hv.scratchPdpt = NULL;
  }

  if (g_Hv.tlbFlushFlags) {
    HvFreePhysicalMemory((PVOID)g_Hv.tlbFlushFlags);
    g_Hv.tlbFlushFlags = NULL;
  }

  if (g_Hv.hostCr3) {
    HvFreePhysicalMemory(g_Hv.hostCr3);
    g_Hv.hostCr3 = NULL;
  }

  if (g_Hv.perCpu) {
    for (ULONG i = 0; i < g_Hv.processorCount; i++) {
      g_Hv.perCpu[i].scratchVa1 = NULL;
      g_Hv.perCpu[i].scratchPte1 = NULL;
      g_Hv.perCpu[i].scratchVa2 = NULL;
      g_Hv.perCpu[i].scratchPte2 = NULL;
      if (g_Hv.perCpu[i].hostSaveArea) {
        HvFreePhysicalMemory(g_Hv.perCpu[i].hostSaveArea);
        g_Hv.perCpu[i].hostSaveArea = NULL;
      }
      if (g_Hv.perCpu[i].guestVmcb) {
        HvFreePhysicalMemory(g_Hv.perCpu[i].guestVmcb);
        g_Hv.perCpu[i].guestVmcb = NULL;
      }
      if (g_Hv.perCpu[i].hostVmcb) {
        HvFreePhysicalMemory(g_Hv.perCpu[i].hostVmcb);
        g_Hv.perCpu[i].hostVmcb = NULL;
      }
      if (g_Hv.perCpu[i].hypervisorStack) {
        HvFreePhysicalMemory(g_Hv.perCpu[i].hypervisorStack);
        g_Hv.perCpu[i].hypervisorStack = NULL;
      }
    }
  }
}
BOOLEAN HvInitializeVirtualizationPhase3(void) {
  if (g_Hv.vendor == CPU_VENDOR_AMD) {

    extern BOOLEAN SvmEnablePhase3(void);
    return SvmEnablePhase3();
  }
  return FALSE;
}

VOID HvDisableVirtualizationPhase3(void) {
  LOG_INFO("HvDisableVirtualizationPhase3 called.");
  HvDevirtualizeAllCores();
}

static ULONG_PTR HvDevirtualizeIpiCallback(ULONG_PTR Argument) {
  UNREFERENCED_PARAMETER(Argument);

  ULONG core = KeGetCurrentProcessorNumber();
  if (core < g_Hv.processorCount && g_Hv.perCpu[core].virtualizationActive) {
    LOG_INFO("Devirtualizing core %u...", core);
    extern VOID SvmDevirtualizeCore(void);
    SvmDevirtualizeCore();
    InterlockedExchange(&g_Hv.perCpu[core].virtualizationActive, 0);
    LOG_OK("Core %u devirtualized.", core);
  }
  return 0;
}

VOID HvDevirtualizeAllCores(void) {
  LOG_INFO("Devirtualizing all cores via IPI broadcast...");
  KeIpiGenericCall(HvDevirtualizeIpiCallback, 0);
  LOG_OK("All cores devirtualized.");
}

static ULONG_PTR HvTlbFlushIpiCallback(ULONG_PTR Argument) {
  UNREFERENCED_PARAMETER(Argument);
  return 0;
}

VOID HvForceTlbFlushAllCores(void) {

  KeIpiGenericCall(HvTlbFlushIpiCallback, 0);
}

BOOLEAN HvSubvertPhase4(void) {
  LOG_INFO("HvSubvertPhase4 called. Attempting hypervisor injection on current "
           "core.");

  extern BOOLEAN SvmSubvertCore(void);
  return SvmSubvertCore();
}

typedef struct _POOL_TRACKER_BIG_PAGES {
  volatile ULONG_PTR Va;
  ULONG Key;
  ULONG PoolType;
  SIZE_T NumberOfBytes;
} POOL_TRACKER_BIG_PAGES, *PPOOL_TRACKER_BIG_PAGES;

static ULONG ScanForRipRelativeTargets(PUCHAR funcBase, ULONG scanLen,
                                        PVOID* outCandidates, ULONG maxCandidates) {
    ULONG count = 0;
    if (!funcBase || scanLen < 8) return 0;

    PVOID lastValidPage = NULL;

    for (ULONG i = 0; i < scanLen - 7 && count < maxCandidates; i++) {

        PVOID curPage = (PVOID)((ULONG_PTR)&funcBase[i] & ~0xFFFULL);
        if (curPage != lastValidPage) {
            if (!MmIsAddressValid(&funcBase[i]))
                break;
            lastValidPage = curPage;
        }

        UCHAR b0 = funcBase[i];

        if (b0 == 0xCC && funcBase[i + 1] == 0xCC) break;

        UCHAR b1 = funcBase[i + 1];
        UCHAR b2 = funcBase[i + 2];

        if (b0 != 0x48 && b0 != 0x4C) continue;

        if (b1 != 0x8B && b1 != 0x8D) continue;

        if ((b2 & 0xC7) != 0x05) continue;

        LONG disp = *(PLONG)&funcBase[i + 3];
        PVOID target = (PVOID)(&funcBase[i + 7] + disp);

        if ((ULONG_PTR)target < 0xFFFF800000000000ULL) continue;

        BOOLEAN duplicate = FALSE;
        for (ULONG d = 0; d < count; d++) {
            if (outCandidates[d] == target) { duplicate = TRUE; break; }
        }
        if (!duplicate) {
            outCandidates[count++] = target;
        }
    }
    return count;
}

BOOLEAN HvCleanBigPoolTrace(void) {
    LOG_INFO("Phase 6b: Cleaning BigPool table entries...");

    if (g_HvPtr && g_Hv.trackedAllocCount < HV_MAX_TRACKED_ALLOCS) {
        g_Hv.trackedAllocs[g_Hv.trackedAllocCount++] = (PVOID)g_HvPtr;
    }

    if (g_HvLogRing && g_Hv.trackedAllocCount < HV_MAX_TRACKED_ALLOCS) {
        g_Hv.trackedAllocs[g_Hv.trackedAllocCount++] = (PVOID)g_HvLogRing;
    }

    if (g_Hv.perCpu && g_Hv.trackedAllocCount < HV_MAX_TRACKED_ALLOCS) {
        g_Hv.trackedAllocs[g_Hv.trackedAllocCount++] = (PVOID)g_Hv.perCpu;
    }
    if (g_Hv.nptPdptPages && g_Hv.trackedAllocCount < HV_MAX_TRACKED_ALLOCS) {
        g_Hv.trackedAllocs[g_Hv.trackedAllocCount++] = (PVOID)g_Hv.nptPdptPages;
    }
    if (g_Hv.nptPdPages && g_Hv.trackedAllocCount < HV_MAX_TRACKED_ALLOCS) {
        g_Hv.trackedAllocs[g_Hv.trackedAllocCount++] = (PVOID)g_Hv.nptPdPages;
    }

    if (g_Hv.trackedAllocCount == 0) {
        LOG_INFO("Phase 6b: No allocations tracked - nothing to clean.");
        return TRUE;
    }

    LOG_INFO("Phase 6b: %u allocations to clean.", g_Hv.trackedAllocCount);

    PVOID allCandidates[128] = {0};
    ULONG totalCandidates = 0;

    static const WCHAR* poolFuncNames[] = {
        L"ExFreePoolWithTag",
        L"ExAllocatePool2",
        L"ExAllocatePoolWithTag",
        L"MmFreeContiguousMemory",
        L"MmFreeContiguousMemorySpecifyCache",
        L"MmAllocateContiguousMemorySpecifyCacheNode",
    };
    static const char* poolFuncLabels[] = {
        "ExFreePoolWithTag",
        "ExAllocatePool2",
        "ExAllocatePoolWithTag",
        "MmFreeContiguousMemory",
        "MmFreeContiguousMemorySpecifyCache",
        "MmAllocateContiguousMemorySpecifyCacheNode",
    };
    static const ULONG poolFuncCount = 6;

    PUCHAR scannedFuncs[64] = {0};
    ULONG scannedFuncCount = 0;

    for (ULONG f = 0; f < poolFuncCount && totalCandidates < 96; f++) {
        UNICODE_STRING funcName;
        RtlInitUnicodeString(&funcName, poolFuncNames[f]);
        PUCHAR funcBase = (PUCHAR)MmGetSystemRoutineAddress(&funcName);
        if (!funcBase || !MmIsAddressValid(funcBase)) {
            LOG_INFO("Phase 6b: %s not found or invalid, skipping.", poolFuncLabels[f]);
            continue;
        }

        scannedFuncs[scannedFuncCount++] = funcBase;

        ULONG found = ScanForRipRelativeTargets(
            funcBase, 0x800,
            &allCandidates[totalCandidates], 96 - totalCandidates);

        LOG_INFO("Phase 6b: %s: %u direct RIP-relative targets.", poolFuncLabels[f], found);
        totalCandidates += found;

        PVOID lastCallPage = NULL;
        for (ULONG i = 0; i < 0x400 && totalCandidates < 96; i++) {
            PVOID callPage = (PVOID)((ULONG_PTR)&funcBase[i] & ~0xFFFULL);
            if (callPage != lastCallPage) {
                if (!MmIsAddressValid(&funcBase[i])) break;
                lastCallPage = callPage;
            }

            if (funcBase[i] == 0xCC && funcBase[i + 1] == 0xCC) break;

            if (funcBase[i] != 0xE8) continue;

            LONG callDisp = *(PLONG)&funcBase[i + 1];
            PUCHAR callTarget = &funcBase[i + 5] + callDisp;

            if ((ULONG_PTR)callTarget < 0xFFFF800000000000ULL) continue;
            if (!MmIsAddressValid(callTarget)) continue;

            BOOLEAN alreadyScanned = FALSE;
            for (ULONG s = 0; s < scannedFuncCount; s++) {

                LONG_PTR diff = (LONG_PTR)(callTarget - scannedFuncs[s]);
                if (diff > -0x100 && diff < 0x100) {
                    alreadyScanned = TRUE;
                    break;
                }
            }
            if (alreadyScanned) continue;
            if (scannedFuncCount < 64)
                scannedFuncs[scannedFuncCount++] = callTarget;

            ULONG callFound = ScanForRipRelativeTargets(
                callTarget, 0x600,
                &allCandidates[totalCandidates], 96 - totalCandidates);

            if (callFound > 0) {
                LOG_INFO("Phase 6b:   -> CALL target at +0x%x: %u targets.",
                         (ULONG)(callTarget - funcBase), callFound);
                totalCandidates += callFound;
            }
        }
    }

    LOG_INFO("Phase 6b: Total unique candidates (direct + CALL targets): %u", totalCandidates);

    if (totalCandidates == 0) {
        LOG_ERROR("Phase 6b: No RIP-relative candidates found in any pool function!");
        return FALSE;
    }

    BOOLEAN allocCleaned[HV_MAX_TRACKED_ALLOCS] = {0};
    ULONG totalCleaned = 0;
    ULONG tablesFound = 0;

    static const ULONG diverseTags[] = {
        'tnoC',
        'dSmM',
        'lPnN',
        'eRcC',
        'kWoI',
        'aFeS',
        'pFxE',
        'tOoP',
        'cPpN',
        'dLbO',
        'iFeR',
        'cMmC',
    };

    for (ULONG c = 0; c < totalCandidates; c++) {

        if (totalCleaned >= g_Hv.trackedAllocCount) break;

        PVOID candidateAddr = allCandidates[c];

        if (!MmIsAddressValid(candidateAddr)) continue;
        if (!MmIsAddressValid((PUCHAR)candidateAddr + 7)) continue;

        ULONG_PTR rawValue = *(ULONG_PTR *)candidateAddr;

        if (!rawValue || rawValue < 0xFFFF800000000000ULL) continue;

        PPOOL_TRACKER_BIG_PAGES tableCandidate = (PPOOL_TRACKER_BIG_PAGES)rawValue;
        if (!MmIsAddressValid(tableCandidate)) continue;

        BOOLEAN isPoolTable = FALSE;
        PVOID lastValPage = NULL;

        for (ULONG e = 0; e < 32768 && !isPoolTable; e++) {
            PVOID eAddr = &tableCandidate[e];
            PVOID ePage = (PVOID)((ULONG_PTR)eAddr & ~0xFFFULL);
            if (ePage != lastValPage) {
                if (!MmIsAddressValid(eAddr)) break;
                lastValPage = ePage;
            }

            ULONG_PTR va = tableCandidate[e].Va;
            if (va == 0 || va == 1) continue;
            ULONG_PTR entryVa = va & ~1ULL;
            if (entryVa < 0xFFFF800000000000ULL) continue;
            SIZE_T entrySize = tableCandidate[e].NumberOfBytes & ~1ULL;
            if (entrySize == 0) entrySize = PAGE_SIZE;

            for (ULONG a = 0; a < g_Hv.trackedAllocCount; a++) {
                ULONG_PTR allocVa = (ULONG_PTR)g_Hv.trackedAllocs[a];
                if (!allocCleaned[a] && allocVa >= entryVa && allocVa < entryVa + entrySize) {
                    isPoolTable = TRUE;
                    break;
                }
            }
        }

        if (!isPoolTable) continue;

        tablesFound++;
        LOG_OK("Phase 6b: Pool table found via candidate %u (base=0x%llx).", c, rawValue);

        ULONG tableSize = 262144;
        PUCHAR pAddr = (PUCHAR)candidateAddr;
        for (int off = -0x20; off <= 0x40; off += 8) {
            if (off == 0) continue;
            PUCHAR sAddr = pAddr + off;
            if (MmIsAddressValid(sAddr) && MmIsAddressValid(sAddr + 3)) {
                ULONG sz = *(ULONG *)sAddr;
                if (sz >= 4096 && sz <= 1048576) {
                    tableSize = sz;
                    LOG_INFO("Phase 6b:   TableSize=%u (offset %+d)", tableSize, off);
                    break;
                }
            }
        }

        ULONG cleanedThisTable = 0;
        ULONG entriesModified = 0;
        PVOID lastValidPage = NULL;
        ULONG entriesScanned = 0;

        for (ULONG e = 0; e < tableSize; e++) {
            PVOID entryAddr = &tableCandidate[e];
            PVOID entryPage = (PVOID)((ULONG_PTR)entryAddr & ~0xFFFULL);

            if (entryPage != lastValidPage) {
                if (!MmIsAddressValid(entryAddr)) break;
                lastValidPage = entryPage;
            }

            entriesScanned++;

            ULONG_PTR va = tableCandidate[e].Va;
            if (va == 0 || va == 1) continue;
            ULONG_PTR entryVa = va & ~1ULL;
            if (entryVa < 0xFFFF800000000000ULL) continue;

            SIZE_T entrySize = tableCandidate[e].NumberOfBytes & ~1ULL;
            if (entrySize == 0) entrySize = PAGE_SIZE;

            BOOLEAN entryMatched = FALSE;
            for (ULONG a = 0; a < g_Hv.trackedAllocCount; a++) {
                if (allocCleaned[a]) continue;
                ULONG_PTR allocVa = (ULONG_PTR)g_Hv.trackedAllocs[a];
                if (allocVa >= entryVa && allocVa < entryVa + entrySize) {
                    allocCleaned[a] = TRUE;
                    totalCleaned++;
                    cleanedThisTable++;
                    entryMatched = TRUE;

                }
            }
            if (entryMatched) {
                tableCandidate[e].Key = diverseTags[entriesModified % 12];
                entriesModified++;
            }
        }

        LOG_INFO("Phase 6b:   Scanned %u entries, %u modified, %u allocs cleaned.",
                 entriesScanned, entriesModified, cleanedThisTable);
    }

    if (totalCleaned < g_Hv.trackedAllocCount) {
        LOG_INFO("Phase 6b: %u allocs not in any BigPool table (sub-page or private).",
                 g_Hv.trackedAllocCount - totalCleaned);
    }

    LOG_OK("Phase 6b: %u table(s) found. Cleaned %u / %u BigPool tags total.",
           tablesFound, totalCleaned, g_Hv.trackedAllocCount);
    return (totalCleaned > 0);
}
