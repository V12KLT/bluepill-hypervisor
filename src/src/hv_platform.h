#ifndef HV_PLATFORM_H
#define HV_PLATFORM_H

#include <ntddk.h>
#include <intrin.h>

#define HV_TAG 'dSmM'

#define HV_MAX_TRACKED_ALLOCS 256

typedef enum _CPU_VENDOR {
    CPU_VENDOR_UNKNOWN,
    CPU_VENDOR_AMD,
    CPU_VENDOR_INTEL
} CPU_VENDOR;

typedef struct _PHV_PER_CPU {
    ULONG_PTR virtualized;
    PVOID hostSaveArea;
    PHYSICAL_ADDRESS hostSaveAreaPhysical;
    PVOID guestVmcb;
    PHYSICAL_ADDRESS guestVmcbPhysical;
    PVOID hostVmcb;
    PHYSICAL_ADDRESS hostVmcbPhysical;
    PVOID hypervisorStack;
    ULONG64 guestEfer;
    ULONG64 guestVmHsavePa;
    ULONG64 guestVmCr;
    volatile LONG virtualizationActive;

    ULONG64 guestDr0;
    ULONG64 guestDr1;
    ULONG64 guestDr2;
    ULONG64 guestDr3;
    ULONG64 guestDr6;
    ULONG64 guestDr7;

    ULONG64 guestApicBase;

    volatile LONG nptTlbFlushPending;

    PVOID scratchVa1;
    PULONG64 scratchPte1;
    PVOID scratchVa2;
    PULONG64 scratchPte2;

    ULONG64 lastGuestCr3;
    volatile LONG cr3RefreshCounter;
    BOOLEAN mapperAllowed;

    BOOLEAN singleStepForNpt;
    PVOID lastModifiedPte;
    ULONG64 savedRealPfn;
    volatile LONG singleStepAge;

    ULONG64 lastNpfGpa;
    ULONG   npfStreakCount;
} PHV_PER_CPU, *PPHV_PER_CPU;

#ifndef NPF_STORM_THRESHOLD
#define NPF_STORM_THRESHOLD 32u
#endif

typedef struct _HV_STATE {
    CPU_VENDOR vendor;
    ULONG processorCount;
    PPHV_PER_CPU perCpu;

    PVOID msrBitmap;
    PHYSICAL_ADDRESS msrBitmapPhysical;
    PVOID iopmBitmap;
    PHYSICAL_ADDRESS iopmBitmapPhysical;

    PVOID hostCr3;
    PHYSICAL_ADDRESS hostCr3Physical;

    ULONG xsaveAreaSize;
    BOOLEAN vgifSupported;
    BOOLEAN decodeAssistsSupported;

    PVOID nptPml4;
    PHYSICAL_ADDRESS nptPml4Physical;
    PVOID* nptPdptPages;
    PVOID* nptPdPages;
    ULONG nptPdptCount;
    ULONG nptPdCount;

    PVOID decoyPages[4];
    PHYSICAL_ADDRESS decoyPagesPhysical[4];

    PVOID scratchPt;
    PVOID scratchPdpt;
    PVOID scratchPd;
    ULONG scratchPml4Slot;

    PVOID iommuMmioBase;
    PHYSICAL_ADDRESS iommuMmioPhysical;
    ULONG64 iommuMmioSize;
    BOOLEAN iommuPresent;
    BOOLEAN iommuEnabled;
    BOOLEAN iommuWeEnabled;
    PVOID iommuDeviceTable;
    PHYSICAL_ADDRESS iommuDeviceTablePhysical;
    PVOID iommuIoPml4;
    PHYSICAL_ADDRESS iommuIoPml4Physical;

    ULONG64 realFeatureControl;

    int cachedCpuid40000000[4];

    ULONG cpuidSteppingRotation;
    UCHAR cpuidBrandRotation;

    volatile LONG* tlbFlushFlags;

    ULONG64 systemCr3KernelSnapshot[256];
    BOOLEAN systemCr3SnapshotValid;

    ULONG stealthDegradedPageCount;

    ULONG64 commMagic;

    ULONG64 bootstrapMagic;

    ULONG64 targetCr3;
    ULONG64 targetUserCr3;
    ULONG64 targetPid;
    PVOID   systemEprocess;

    ULONG eprocessPidOffset;
    ULONG eprocessLinksOffset;
    ULONG eprocessDirTableOffset;
    ULONG eprocessPebOffset;
    ULONG eprocessImageNameOffset;
    ULONG eprocessSectionBaseOffset;

    PPHYSICAL_MEMORY_RANGE physMemRanges;
    ULONG64 lastCr3ScanPa;
    ULONG   cr3ScanSweepCount;

    PVOID trackedAllocs[HV_MAX_TRACKED_ALLOCS];
    ULONG trackedAllocCount;

    ULONG64 ntoskrnlTextBase;
    ULONG64 ntoskrnlTextSize;

    PVOID   driverImageBase;
    ULONG   driverImageSize;
    BOOLEAN pdataRegistered;

    volatile LONG killSwitch;

    volatile ULONG64 expectedDispatcherHash;
    volatile ULONG   dispatcherIntegrityFailed;

    ULONG mcBankCount;
} HV_STATE, *PHV_STATE;

#define HV_DISPATCH_CHECK_BYTES 2048

extern PHV_STATE g_HvPtr;
#define g_Hv (*g_HvPtr)

__forceinline static ULONG64 HvFnv1aCode(const volatile UCHAR *code, ULONG bytes) {
    ULONG64 h = 0xCBF29CE484222325ULL;
    for (ULONG i = 0; i < bytes; ++i) {
        h ^= (ULONG64)code[i];
        h *= 0x100000001B3ULL;
    }
    return h;
}

#pragma section(".logstr$A", read)
#pragma section(".logstr$M", read)
#pragma section(".logstr$Z", read)

#define HV_LOG_RING_ENTRY_SIZE  256
#define HV_LOG_RING_ENTRY_COUNT 512
#define HV_LOG_RING_SIZE        (HV_LOG_RING_ENTRY_SIZE * HV_LOG_RING_ENTRY_COUNT)

typedef struct _HV_LOG_RING {
    volatile LONG writeIndex;
    volatile LONG readIndex;
    LONG capacity;
    CHAR buffer[1];
} HV_LOG_RING, *PHV_LOG_RING;

extern PHV_LOG_RING g_HvLogRing;

BOOLEAN HvLogRingInit(void);
VOID    HvLogFlush(void);
VOID    HvLogRingFree(void);

VOID HvLogRingWrite(const char* formatted, int len);

#ifndef NDEBUG

int __cdecl _vsnprintf(char*, size_t, const char*, va_list);
int __cdecl _snprintf(char*, size_t, const char*, ...);

#define LOG_INFO(fmt, ...) do { \
    __declspec(allocate(".logstr$M")) static const char _fmt[] = "[ElevationHV] [*] " fmt "\n"; \
    if (g_HvLogRing) { \
        char _buf[HV_LOG_RING_ENTRY_SIZE]; \
        int _n = _snprintf(_buf, sizeof(_buf) - 1, _fmt, ##__VA_ARGS__); \
        if (_n < 0) _n = sizeof(_buf) - 1; \
        _buf[_n] = '\0'; \
        HvLogRingWrite(_buf, _n); \
    } \
} while(0)
#define LOG_ERROR(fmt, ...) do { \
    __declspec(allocate(".logstr$M")) static const char _fmt[] = "[ElevationHV] [-] " fmt "\n"; \
    if (g_HvLogRing) { \
        char _buf[HV_LOG_RING_ENTRY_SIZE]; \
        int _n = _snprintf(_buf, sizeof(_buf) - 1, _fmt, ##__VA_ARGS__); \
        if (_n < 0) _n = sizeof(_buf) - 1; \
        _buf[_n] = '\0'; \
        HvLogRingWrite(_buf, _n); \
    } \
} while(0)
#define LOG_OK(fmt, ...) do { \
    __declspec(allocate(".logstr$M")) static const char _fmt[] = "[ElevationHV] [+] " fmt "\n"; \
    if (g_HvLogRing) { \
        char _buf[HV_LOG_RING_ENTRY_SIZE]; \
        int _n = _snprintf(_buf, sizeof(_buf) - 1, _fmt, ##__VA_ARGS__); \
        if (_n < 0) _n = sizeof(_buf) - 1; \
        _buf[_n] = '\0'; \
        HvLogRingWrite(_buf, _n); \
    } \
} while(0)
#else
#define LOG_INFO(fmt, ...) ((void)0)
#define LOG_ERROR(fmt, ...) ((void)0)
#define LOG_OK(fmt, ...) ((void)0)
#endif

CPU_VENDOR HvGetCpuVendor(void);

PVOID HvAllocatePhysicalMemory(SIZE_T NumberOfBytes, PPHYSICAL_ADDRESS OutPhysical);
VOID HvFreePhysicalMemory(PVOID VirtualAddress);
BOOLEAN HvAllocatePhase2(void);
VOID HvFreePhase2(void);
BOOLEAN HvInitializeVirtualizationPhase3(void);
VOID HvDisableVirtualizationPhase3(void);
BOOLEAN HvSubvertPhase4(void);
VOID HvDevirtualizeAllCores(void);
VOID HvRefreshHostCr3(ULONG64 guestCr3);

VOID HvForceTlbFlushAllCores(void);
VOID HvGcStaleHostCr3Slots(ULONG64 guestCr3);

BOOLEAN HvCleanBigPoolTrace(void);

#endif
