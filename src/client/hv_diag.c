#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <windows.h>
#include <intrin.h>

#define HV_MAGIC_SEED         0x46475248ULL
#define HV_MAGIC_MIX(bootId)  (HV_MAGIC_SEED ^ ((uint64_t)(bootId) * 0x5DEECE66DULL + 0xBULL))

extern uint64_t HvVmmcall(uint64_t magic, uint64_t command,
                           uint64_t arg1, uint64_t arg2, uint64_t arg3);

int main(void) {
    printf("=== ForgeHV Diagnostic ===\n\n");

    volatile uint8_t* kuser = (volatile uint8_t*)0x7FFE0000;

    uint32_t val_2bc = *(volatile uint32_t*)(kuser + 0x2BC);
    uint32_t val_2c0 = *(volatile uint32_t*)(kuser + 0x2C0);
    uint32_t val_2c4 = *(volatile uint32_t*)(kuser + 0x2C4);
    uint32_t val_2c8 = *(volatile uint32_t*)(kuser + 0x2C8);
    uint32_t val_2cc = *(volatile uint32_t*)(kuser + 0x2CC);
    uint32_t val_300 = *(volatile uint32_t*)(kuser + 0x300);
    uint32_t val_304 = *(volatile uint32_t*)(kuser + 0x304);

    uint32_t ntMajor = *(volatile uint32_t*)(kuser + 0x26C);
    uint32_t ntMinor = *(volatile uint32_t*)(kuser + 0x270);
    uint32_t ntBuild = *(volatile uint32_t*)(kuser + 0x260);

    printf("[KUSER] NtMajor=0x%X NtMinor=0x%X field_260=0x%X\n", ntMajor, ntMinor, ntBuild);
    printf("[KUSER] Offsets around BootId:\n");
    printf("  +0x2BC = %u (0x%X)\n", val_2bc, val_2bc);
    printf("  +0x2C0 = %u (0x%X)  <-- currently used as BootId\n", val_2c0, val_2c0);
    printf("  +0x2C4 = %u (0x%X)\n", val_2c4, val_2c4);
    printf("  +0x2C8 = %u (0x%X)\n", val_2c8, val_2c8);
    printf("  +0x2CC = %u (0x%X)\n", val_2cc, val_2cc);
    printf("  +0x300 = %u (0x%X)\n", val_300, val_300);
    printf("  +0x304 = %u (0x%X)\n", val_304, val_304);
    printf("\n");

    uint64_t magic = HV_MAGIC_MIX(val_2c0);
    if (magic == 0 || magic == 0x464F5247ULL)
        magic ^= 0xDEADCAFEULL;
    printf("[MAGIC] Using BootId=%u -> magic=0x%llx\n\n", val_2c0, magic);

    {
        int info[4];
        __cpuid(info, 0x80000001);
        int svmBit = (info[2] >> 2) & 1;
        printf("[CPU] CPUID 0x80000001 ECX=0x%X, SVM bit=%d\n", info[2], svmBit);
    }

    {
        int info[4];
        __cpuidex(info, 0x40000000, 0);
        printf("[CPUID 40000000] EAX=0x%X EBX=0x%X ECX=0x%X EDX=0x%X\n",
               info[0], info[1], info[2], info[3]);

        if (info[0] >= 0x40000000) {
            char vendor[13] = {0};
            *(int*)&vendor[0] = info[1];
            *(int*)&vendor[4] = info[2];
            *(int*)&vendor[8] = info[3];
            printf("[CPUID] Hypervisor vendor: '%s'\n", vendor);
        } else {
            printf("[CPUID] No hypervisor advertising via CPUID 0x40000000\n");
        }
    }

    printf("\n[TEST] Attempting VMMCALL with magic=0x%llx, CMD=PING...\n", magic);
    fflush(stdout);

    uint64_t result = 0;
    BOOL vmmcallWorked = FALSE;

    __try {
        result = HvVmmcall(magic, 0x01 , 0, 0, 0);
        vmmcallWorked = TRUE;
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        DWORD code = GetExceptionCode();
        printf("[TEST] VMMCALL caused exception 0x%08X", code);
        if (code == 0xC000001D) printf(" (STATUS_ILLEGAL_INSTRUCTION / #UD)");
        if (code == 0xC0000005) printf(" (ACCESS_VIOLATION)");
        printf("\n");
        printf("[TEST] This means the hypervisor is NOT running or magic is wrong.\n");
    }

    if (vmmcallWorked) {
        printf("[TEST] VMMCALL returned 0x%llx\n", result);
        if (result != 0 && result != 0xFFFFFFFF) {
            printf("[TEST] SUCCESS! HV is running. Rolling magic = 0x%llx\n", result);
        } else {
            printf("[TEST] HV responded but returned failure.\n");
        }
    }

    printf("\nPress any key to exit...\n");
    system("pause >nul");
    return 0;
}
