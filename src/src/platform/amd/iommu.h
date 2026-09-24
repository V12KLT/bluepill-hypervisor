#ifndef _IOMMU_H_
#define _IOMMU_H_

#include "../../hv_platform.h"

#define IOMMU_PCI_CAP_ID            0x0F

#define IOMMU_MMIO_DEV_TAB_BASE     0x0000
#define IOMMU_MMIO_CMD_BUF_BASE     0x0008
#define IOMMU_MMIO_EVT_LOG_BASE     0x0010
#define IOMMU_MMIO_CONTROL          0x0018
#define IOMMU_MMIO_EXCL_BASE        0x0020
#define IOMMU_MMIO_EXCL_LIMIT       0x0028
#define IOMMU_MMIO_CMD_BUF_HEAD     0x2000
#define IOMMU_MMIO_CMD_BUF_TAIL     0x2008
#define IOMMU_MMIO_EVT_LOG_HEAD     0x2010
#define IOMMU_MMIO_EVT_LOG_TAIL     0x2018
#define IOMMU_MMIO_STATUS           0x2020

#define IOMMU_CTRL_IOMMU_EN         (1ULL << 0)
#define IOMMU_CTRL_HT_TUN_EN        (1ULL << 1)
#define IOMMU_CTRL_EVT_LOG_EN       (1ULL << 2)
#define IOMMU_CTRL_EVT_INT_EN       (1ULL << 3)
#define IOMMU_CTRL_CMD_BUF_EN       (1ULL << 12)

#pragma pack(push, 1)
typedef struct _IOMMU_DTE {

    ULONG64 Valid : 1;
    ULONG64 TranslationValid : 1;
    ULONG64 Reserved0 : 5;
    ULONG64 HostPageTableRootLow : 3;
    ULONG64 Reserved1 : 2;
    ULONG64 PageTableRoot : 40;
    ULONG64 PPRAutoResponse : 1;
    ULONG64 IOTLB : 1;
    ULONG64 SD : 1;
    ULONG64 Reserved2 : 2;
    ULONG64 Reserved3 : 1;
    ULONG64 DomainID : 6;

    ULONG64 DomainID2 : 10;
    ULONG64 GuestCR3TableEn : 1;
    ULONG64 GLXBits : 2;
    ULONG64 GuestCR3Root : 40;
    ULONG64 IntReserved1 : 3;
    ULONG64 IntDomainID : 8;

    ULONG64 SysMgt : 2;
    ULONG64 Reserved4 : 1;
    ULONG64 IntTabLen : 4;
    ULONG64 Reserved5 : 1;
    ULONG64 IntTableRootLow : 6;
    ULONG64 IntTableRoot : 40;
    ULONG64 Reserved6 : 4;
    ULONG64 IntCtl : 2;
    ULONG64 Reserved7 : 1;
    ULONG64 IntValid : 1;
    ULONG64 Reserved8 : 2;

    ULONG64 Reserved9[1];
} IOMMU_DTE, *PIOMMU_DTE;
#pragma pack(pop)

C_ASSERT(sizeof(IOMMU_DTE) == 32);

#pragma pack(push, 1)
typedef union _IOMMU_PTE {
    ULONG64 AsUInt64;
    struct {
        ULONG64 Present : 1;
        ULONG64 Reserved0 : 4;
        ULONG64 Accessed : 1;
        ULONG64 Dirty : 1;
        ULONG64 PageSize : 1;
        ULONG64 Reserved1 : 1;
        ULONG64 NextLevel : 3;
        ULONG64 PageFrameNumber : 40;
        ULONG64 Reserved2 : 7;
        ULONG64 UPermission : 1;
        ULONG64 FC : 1;
        ULONG64 IR : 1;
        ULONG64 IW : 1;
        ULONG64 Reserved3 : 1;
    } Fields;
} IOMMU_PTE, *PIOMMU_PTE;
#pragma pack(pop)

C_ASSERT(sizeof(IOMMU_PTE) == 8);

#pragma pack(push, 1)
typedef struct _IOMMU_CMD_ENTRY {
    ULONG64 Operand0;
    ULONG64 Operand1;
} IOMMU_CMD_ENTRY, *PIOMMU_CMD_ENTRY;
#pragma pack(pop)

C_ASSERT(sizeof(IOMMU_CMD_ENTRY) == 16);

#define IOMMU_CMD_COMPLETION_WAIT   0x01
#define IOMMU_CMD_INVALIDATE_PAGES  0x03
#define IOMMU_CMD_INVALIDATE_ALL    0x08

#define IOMMU_PT_ENTRIES            512
#define IOMMU_PT_LEVELS_MAX         4
#define IOMMU_PAGE_SIZE             0x1000ULL
#define IOMMU_LARGE_PAGE_2MB        0x200000ULL
#define IOMMU_LARGE_PAGE_1GB        0x40000000ULL

BOOLEAN IommuEnable(void);

BOOLEAN IommuHideHypervisorPages(void);

VOID IommuCleanup(void);

#endif
