#include "iommu.h"
#include "npt.h"

static ULONG PciReadConfig32(ULONG bus, ULONG device, ULONG function, ULONG offset) {
    ULONG address = (1UL << 31) | (bus << 16) | (device << 11) | (function << 8) | (offset & 0xFC);
    __outdword(0xCF8, address);
    return __indword(0xCFC);
}

static BOOLEAN IommuDiscoverPci(PHYSICAL_ADDRESS* OutMmioBase, ULONG64* OutMmioSize) {
    for (ULONG dev = 0; dev < 32; dev++) {
        for (ULONG func = 0; func < 8; func++) {
            ULONG vendorDevice = PciReadConfig32(0, dev, func, 0x00);

            if (vendorDevice == 0xFFFFFFFF || vendorDevice == 0)
                continue;

            if ((vendorDevice & 0xFFFF) != 0x1022)
                continue;

            ULONG statusCmd = PciReadConfig32(0, dev, func, 0x04);
            if (!((statusCmd >> 16) & (1 << 4)))
                continue;

            ULONG capPtr = PciReadConfig32(0, dev, func, 0x34) & 0xFC;
            ULONG capCount = 0;

            while (capPtr >= 0x40 && capPtr < 0x100 && capCount < 48) {
                capCount++;
                ULONG capHeader = PciReadConfig32(0, dev, func, capPtr);
                ULONG capId = capHeader & 0xFF;

                if (capId == 0x0F) {

                    ULONG mmioBaseLow = PciReadConfig32(0, dev, func, capPtr + 0x04);
                    ULONG mmioBaseHigh = PciReadConfig32(0, dev, func, capPtr + 0x08);
                    ULONG64 mmioBase = ((ULONG64)mmioBaseHigh << 32) | (mmioBaseLow & 0xFFFFC000UL);

                    if (mmioBase && mmioBase != 0xFFFFC000ULL) {
                        OutMmioBase->QuadPart = (LONGLONG)mmioBase;
                        *OutMmioSize = 0x4000;
                        LOG_OK("Phase 5: IOMMU found at PCI 0:%u.%u, MMIO=0x%llx",
                               dev, func, mmioBase);
                        return TRUE;
                    }
                }

                capPtr = (capHeader >> 8) & 0xFC;
            }
        }
    }

    return FALSE;
}

static ULONG64 IommuReadMmio64(PVOID base, ULONG offset) {
    return *(volatile ULONG64*)((PUCHAR)base + offset);
}

static VOID IommuWriteMmio64(PVOID base, ULONG offset, ULONG64 value) {
    *(volatile ULONG64*)((PUCHAR)base + offset) = value;
}

static PVOID IommuMapPhysPage(PHYSICAL_ADDRESS pa) {
    PHYSICAL_ADDRESS aligned;
    aligned.QuadPart = pa.QuadPart & ~0xFFFLL;
    if (aligned.QuadPart == 0) return NULL;
    return MmMapIoSpace(aligned, 0x1000, MmNonCached);
}

static VOID IommuUnmapPhysPage(PVOID va) {
    if (va) MmUnmapIoSpace(va, 0x1000);
}

static BOOLEAN IommuHidePageInIoPageTable(
    ULONG64 IoPageTableRootPa,
    ULONG   RootLevel,
    ULONG64 TargetHpa
) {
    ULONG64 tablePa = IoPageTableRootPa & ~0xFFFULL;
    ULONG level = RootLevel;

    while (level >= 1 && level <= 4) {
        PHYSICAL_ADDRESS phys;
        phys.QuadPart = (LONGLONG)tablePa;
        PIOMMU_PTE table = (PIOMMU_PTE)IommuMapPhysPage(phys);
        if (!table) return FALSE;

        ULONG shift;
        switch (level) {
            case 4: shift = 39; break;
            case 3: shift = 30; break;
            case 2: shift = 21; break;
            case 1: shift = 12; break;
            default:
                IommuUnmapPhysPage(table);
                return FALSE;
        }

        ULONG index = (ULONG)((TargetHpa >> shift) & 0x1FF);
        PIOMMU_PTE entry = &table[index];

        if (!entry->Fields.Present) {
            IommuUnmapPhysPage(table);
            return FALSE;
        }

        if (level == 1 || entry->Fields.PageSize) {
            ULONG decoyIndex = (ULONG)((TargetHpa >> 12) % 4);
            entry->Fields.PageFrameNumber = g_Hv.decoyPagesPhysical[decoyIndex].QuadPart >> 12;
            IommuUnmapPhysPage(table);
            return TRUE;
        }

        ULONG64 nextPa = (ULONG64)entry->Fields.PageFrameNumber << 12;
        IommuUnmapPhysPage(table);

        tablePa = nextPa;
        level--;
    }

    return FALSE;
}

static BOOLEAN IommuBuildIdentityPageTable(void) {
    g_Hv.iommuIoPml4 = HvAllocatePhysicalMemory(0x1000, &g_Hv.iommuIoPml4Physical);
    if (!g_Hv.iommuIoPml4) return FALSE;

    PIOMMU_PTE pml4 = (PIOMMU_PTE)g_Hv.iommuIoPml4;

    for (ULONG pml4i = 0; pml4i < NPT_PDPT_COUNT; pml4i++) {
        PHYSICAL_ADDRESS pdptPhys;
        PVOID pdptVa = HvAllocatePhysicalMemory(0x1000, &pdptPhys);
        if (!pdptVa) return FALSE;

        PIOMMU_PTE pdpt = (PIOMMU_PTE)pdptVa;

        for (ULONG pdpti = 0; pdpti < 512; pdpti++) {
            PHYSICAL_ADDRESS pdPhys;
            PVOID pdVa = HvAllocatePhysicalMemory(0x1000, &pdPhys);
            if (!pdVa) return FALSE;

            PIOMMU_PTE pd = (PIOMMU_PTE)pdVa;

            for (ULONG pdi = 0; pdi < 512; pdi++) {
                ULONG64 physAddr = ((ULONG64)pml4i << 39) |
                                   ((ULONG64)pdpti << 30) |
                                   ((ULONG64)pdi << 21);

                pd[pdi].AsUInt64 = 0;
                pd[pdi].Fields.Present = 1;
                pd[pdi].Fields.PageSize = 1;
                pd[pdi].Fields.IR = 1;
                pd[pdi].Fields.IW = 1;
                pd[pdi].Fields.PageFrameNumber = physAddr >> 12;
            }

            pdpt[pdpti].AsUInt64 = 0;
            pdpt[pdpti].Fields.Present = 1;
            pdpt[pdpti].Fields.IR = 1;
            pdpt[pdpti].Fields.IW = 1;
            pdpt[pdpti].Fields.NextLevel = 1;
            pdpt[pdpti].Fields.PageFrameNumber = pdPhys.QuadPart >> 12;
        }

        pml4[pml4i].AsUInt64 = 0;
        pml4[pml4i].Fields.Present = 1;
        pml4[pml4i].Fields.IR = 1;
        pml4[pml4i].Fields.IW = 1;
        pml4[pml4i].Fields.NextLevel = 2;
        pml4[pml4i].Fields.PageFrameNumber = pdptPhys.QuadPart >> 12;
    }

    return TRUE;
}

static BOOLEAN IommuBuildDeviceTable(ULONG64 IoPageTableRootPa) {

    ULONG dteCount = 256;
    SIZE_T dtSize = (SIZE_T)dteCount * sizeof(IOMMU_DTE);

    g_Hv.iommuDeviceTable = HvAllocatePhysicalMemory(dtSize, &g_Hv.iommuDeviceTablePhysical);
    if (!g_Hv.iommuDeviceTable) return FALSE;

    PIOMMU_DTE dt = (PIOMMU_DTE)g_Hv.iommuDeviceTable;

    for (ULONG i = 0; i < dteCount; i++) {
        RtlZeroMemory(&dt[i], sizeof(IOMMU_DTE));
        dt[i].Valid = 1;
        dt[i].TranslationValid = 1;
        dt[i].HostPageTableRootLow = 4;
        dt[i].PageTableRoot = (ULONG64)(IoPageTableRootPa >> 12);
    }

    return TRUE;
}

BOOLEAN IommuEnable(void) {
    PHYSICAL_ADDRESS mmioPhys = {0};
    ULONG64 mmioSize = 0;

    if (!IommuDiscoverPci(&mmioPhys, &mmioSize)) {
        LOG_INFO("Phase 5: IOMMU not found on PCI bus. DMA protection unavailable.");
        g_Hv.iommuPresent = FALSE;
        return FALSE;
    }

    g_Hv.iommuPresent = TRUE;
    g_Hv.iommuMmioPhysical = mmioPhys;
    g_Hv.iommuMmioSize = mmioSize;

    g_Hv.iommuMmioBase = MmMapIoSpace(mmioPhys, (SIZE_T)mmioSize, MmNonCached);
    if (!g_Hv.iommuMmioBase) {
        LOG_ERROR("Phase 5: Failed to map IOMMU MMIO at 0x%llx", mmioPhys.QuadPart);
        return FALSE;
    }

    ULONG64 ctrl = IommuReadMmio64(g_Hv.iommuMmioBase, IOMMU_MMIO_CONTROL);
    g_Hv.iommuEnabled = (ctrl & IOMMU_CTRL_IOMMU_EN) != 0;

    if (g_Hv.iommuEnabled) {

        LOG_OK("Phase 5: IOMMU already enabled by OS. DMA isolation provided by OS.");
        MmUnmapIoSpace(g_Hv.iommuMmioBase, (SIZE_T)mmioSize);
        g_Hv.iommuMmioBase = NULL;
        return FALSE;
    } else {

        LOG_OK("Phase 5: IOMMU present but disabled. Skipping (NPT protection sufficient).");
        MmUnmapIoSpace(g_Hv.iommuMmioBase, (SIZE_T)mmioSize);
        g_Hv.iommuMmioBase = NULL;
        return FALSE;
    }
}

BOOLEAN IommuHideHypervisorPages(void) {
    if (!g_Hv.iommuPresent || !g_Hv.iommuEnabled || !g_Hv.iommuMmioBase)
        return FALSE;

    ULONG64 dtBaseReg = IommuReadMmio64(g_Hv.iommuMmioBase, IOMMU_MMIO_DEV_TAB_BASE);
    ULONG64 dtBasePa = dtBaseReg & ~0x1FFULL;
    ULONG dtSizeField = (ULONG)(dtBaseReg & 0x1FF);
    ULONG dtEntries = (dtSizeField + 1) * 128;
    if (dtEntries > 65536) dtEntries = 65536;

    ULONG64 hpasToHide[256];
    ULONG hpaCount = 0;

    if (g_Hv.msrBitmapPhysical.QuadPart) {
        hpasToHide[hpaCount++] = g_Hv.msrBitmapPhysical.QuadPart;
        hpasToHide[hpaCount++] = g_Hv.msrBitmapPhysical.QuadPart + 0x1000;
    }
    if (g_Hv.iopmBitmapPhysical.QuadPart) {
        for (ULONG p = 0; p < 3; p++)
            hpasToHide[hpaCount++] = g_Hv.iopmBitmapPhysical.QuadPart + p * 0x1000;
    }
    for (ULONG i = 0; i < g_Hv.processorCount && hpaCount < 240; i++) {
        if (g_Hv.perCpu[i].guestVmcbPhysical.QuadPart)
            hpasToHide[hpaCount++] = g_Hv.perCpu[i].guestVmcbPhysical.QuadPart;
        if (g_Hv.perCpu[i].hostVmcbPhysical.QuadPart)
            hpasToHide[hpaCount++] = g_Hv.perCpu[i].hostVmcbPhysical.QuadPart;
        if (g_Hv.perCpu[i].hostSaveAreaPhysical.QuadPart)
            hpasToHide[hpaCount++] = g_Hv.perCpu[i].hostSaveAreaPhysical.QuadPart;
        if (g_Hv.perCpu[i].hypervisorStack) {
            PHYSICAL_ADDRESS stackPhys = MmGetPhysicalAddress(g_Hv.perCpu[i].hypervisorStack);
            for (ULONG p = 0; p < 6 && hpaCount < 256; p++)
                hpasToHide[hpaCount++] = stackPhys.QuadPart + p * 0x1000;
        }
    }

    ULONG hiddenCount = 0;
    ULONG dtesPerPage = 4096 / sizeof(IOMMU_DTE);
    ULONG totalDtPages = (dtEntries + dtesPerPage - 1) / dtesPerPage;

    for (ULONG pageIdx = 0; pageIdx < totalDtPages; pageIdx++) {
        PHYSICAL_ADDRESS pagePhys;
        pagePhys.QuadPart = (LONGLONG)(dtBasePa + (ULONG64)pageIdx * 0x1000);

        PIOMMU_DTE dtPage = (PIOMMU_DTE)IommuMapPhysPage(pagePhys);
        if (!dtPage) continue;

        ULONG startDte = pageIdx * dtesPerPage;
        ULONG endDte = startDte + dtesPerPage;
        if (endDte > dtEntries) endDte = dtEntries;

        for (ULONG dteIdx = startDte; dteIdx < endDte; dteIdx++) {
            ULONG localIdx = dteIdx - startDte;
            PIOMMU_DTE dte = &dtPage[localIdx];

            if (!dte->Valid || !dte->TranslationValid || !dte->PageTableRoot)
                continue;

            ULONG64 ioPageTablePa = (ULONG64)dte->PageTableRoot << 12;
            ULONG ptLevel = (ULONG)dte->HostPageTableRootLow;
            if (ptLevel == 0 || ptLevel > 4) continue;

            for (ULONG h = 0; h < hpaCount; h++) {
                if (IommuHidePageInIoPageTable(ioPageTablePa, ptLevel, hpasToHide[h])) {
                    hiddenCount++;
                }
            }
        }

        IommuUnmapPhysPage(dtPage);
    }

    LOG_OK("Phase 5: Hidden %u entries across IOMMU I/O page tables.", hiddenCount);
    return TRUE;
}

VOID IommuCleanup(void) {
    if (g_Hv.iommuWeEnabled && g_Hv.iommuMmioBase) {
        ULONG64 ctrl = IommuReadMmio64(g_Hv.iommuMmioBase, IOMMU_MMIO_CONTROL);
        ctrl &= ~IOMMU_CTRL_IOMMU_EN;
        IommuWriteMmio64(g_Hv.iommuMmioBase, IOMMU_MMIO_CONTROL, ctrl);
        g_Hv.iommuEnabled = FALSE;
        g_Hv.iommuWeEnabled = FALSE;
    }

    if (g_Hv.iommuMmioBase) {
        MmUnmapIoSpace(g_Hv.iommuMmioBase, (SIZE_T)g_Hv.iommuMmioSize);
        g_Hv.iommuMmioBase = NULL;
    }

    if (g_Hv.iommuDeviceTable) {
        HvFreePhysicalMemory(g_Hv.iommuDeviceTable);
        g_Hv.iommuDeviceTable = NULL;
    }

    if (g_Hv.iommuIoPml4) {
        HvFreePhysicalMemory(g_Hv.iommuIoPml4);
        g_Hv.iommuIoPml4 = NULL;
    }
}
